from __future__ import annotations

import argparse
import os
import importlib.metadata as importlib_metadata
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Iterable, Sequence

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_CONSTRAINT_COMMAND = "security-constraints"
INSTALLED_PACKAGES_SCRIPT = """\
import json
from importlib import metadata

print(json.dumps([
    {"name": dist.metadata.get("Name"), "version": dist.version}
    for dist in metadata.distributions()
]))
"""


@dataclass(frozen=True)
class PackageRecord:
    name: str
    version: Version


@dataclass(frozen=True)
class PackageSource:
    label: str
    packages: list[PackageRecord]


@dataclass(frozen=True)
class ExecutableReference:
    executable_path: Path
    interpreter_path: Path


@dataclass(frozen=True)
class Violation:
    source_label: str
    package_name: str
    package_version: Version
    constraint: str


def parse_args(argv: Sequence[str] | None = None) -> tuple[argparse.Namespace, list[str]]:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--constraints-command",
        default="",
        help="Override the security-constraints executable name.",
    )
    parser = argparse.ArgumentParser(
        prog="uv-constraints-check",
        description="Check lockfiles, installed packages, or executable scripts against constraints from security-constraints.",
        parents=[common_parser],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    lockfile_parser = subparsers.add_parser(
        "lockfile",
        help="Check a uv.lock file.",
        description="Check a uv.lock file against security constraints.",
        parents=[common_parser],
    )
    lockfile_parser.add_argument(
        "path",
        nargs="?",
        default="uv.lock",
        help="Path to uv.lock. Defaults to ./uv.lock.",
    )

    installed_parser = subparsers.add_parser(
        "installed",
        help="Check installed packages in a Python environment.",
        description="Check installed packages in a Python environment against security constraints.",
        parents=[common_parser],
    )
    installed_parser.add_argument(
        "--python",
        default="",
        help="Python executable to inspect. Defaults to the current interpreter.",
    )

    executables_parser = subparsers.add_parser(
        "executables",
        help="Check Python scripts found on PATH.",
        description="Check Python scripts found on PATH against security constraints.",
        parents=[common_parser],
    )
    executables_parser.add_argument(
        "--all-executables",
        action="store_true",
        help="Scan all PATH entries instead of only the home directory.",
    )

    args, passthrough = parser.parse_known_args(argv)
    if args.command == "lockfile" and _contains_any_option(passthrough, ("--python", "--all-executables")):
        parser.error("--python and --all-executables are only valid with their matching subcommands.")
    if args.command == "installed" and _contains_any_option(passthrough, ("--all-executables",)):
        parser.error("--all-executables is only valid with executables.")
    if args.command == "executables" and _contains_any_option(passthrough, ("--python",)):
        parser.error("--python is only valid with installed.")
    return args, passthrough


def resolve_constraints_command(explicit_command: str) -> str:
    command = explicit_command or DEFAULT_CONSTRAINT_COMMAND
    if command != DEFAULT_CONSTRAINT_COMMAND:
        raise ValueError(
            "Only the correct executable name 'security-constraints' is accepted."
        )
    if which(command) is None:
        raise FileNotFoundError(f"Could not find {DEFAULT_CONSTRAINT_COMMAND} in PATH.")
    return command


def _contains_any_option(arguments: Sequence[str], options: Sequence[str]) -> bool:
    for argument in arguments:
        for option in options:
            if argument == option or argument.startswith(f"{option}="):
                return True
    return False


def fetch_constraints(command: str, passthrough_args: Iterable[str] = ()) -> str:
    sanitized_args = _sanitize_passthrough_args(passthrough_args)
    completed = subprocess.run(
        [command, "--output", "-", *sanitized_args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _sanitize_passthrough_args(passthrough_args: Iterable[str]) -> list[str]:
    filtered: list[str] = []
    skip_next = False
    for arg in passthrough_args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--output":
            skip_next = True
            continue
        if arg.startswith("--output="):
            continue
        filtered.append(arg)
    return filtered


def load_lock_packages(lockfile: Path) -> list[PackageRecord]:
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    packages: list[PackageRecord] = []
    for entry in data.get("package", []):
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        try:
            parsed_version = Version(version)
        except InvalidVersion as exc:
            raise ValueError(f"Invalid version in {lockfile}: {name} {version!r}") from exc
        packages.append(PackageRecord(name=name, version=parsed_version))
    return packages


def load_installed_packages(python_executable: str = "") -> list[PackageRecord]:
    if python_executable:
        return load_installed_packages_from_python(python_executable)
    return load_current_installed_packages()


def load_current_installed_packages() -> list[PackageRecord]:
    return _load_packages_from_distributions(importlib_metadata.distributions())


def load_installed_packages_from_python(python_executable: str) -> list[PackageRecord]:
    python_path = Path(python_executable)
    if not python_path.exists():
        raise FileNotFoundError(f"Python executable not found: {python_executable}")
    if not os.access(python_path, os.X_OK):
        raise PermissionError(f"Python executable is not executable: {python_executable}")
    completed = subprocess.run(
        [str(python_path), "-c", INSTALLED_PACKAGES_SCRIPT],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Could not parse installed package list from Python output.") from exc
    packages: list[PackageRecord] = []
    for entry in payload:
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        try:
            parsed_version = Version(version)
        except InvalidVersion as exc:
            raise ValueError(
                f"Invalid version from {python_executable}: {name} {version!r}"
            ) from exc
        packages.append(PackageRecord(name=name, version=parsed_version))
    return packages


def load_lockfile_source(lockfile: Path) -> PackageSource:
    return PackageSource(
        label=f"uv.lock ({lockfile.resolve()})",
        packages=load_lock_packages(lockfile),
    )


def load_installed_source(python_executable: str = "") -> PackageSource:
    python_path = Path(python_executable) if python_executable else Path(sys.executable)
    return PackageSource(
        label=f"installed packages ({_python_environment_label(python_path)})",
        packages=load_installed_packages(python_executable),
    )


def load_executable_sources(
    path_value: str | None = None,
    *,
    home_only: bool = True,
) -> list[PackageSource]:
    sources: list[PackageSource] = []
    package_cache: dict[Path, list[PackageRecord]] = {}
    home_root = Path.home().resolve()
    for reference in discover_python_executables(path_value, home_only=home_only):
        if home_only and (
            not _is_under_home(reference.executable_path, home_root)
            or not _is_under_home(reference.interpreter_path, home_root)
        ):
            continue
        try:
            packages = package_cache.get(reference.interpreter_path)
            if packages is None:
                packages = load_installed_packages_from_python(str(reference.interpreter_path))
                package_cache[reference.interpreter_path] = packages
        except (FileNotFoundError, PermissionError, subprocess.CalledProcessError, ValueError) as exc:
            print(f"Skipping {reference.executable_path}: {exc}", file=sys.stderr)
            continue
        sources.append(
            PackageSource(
                label=(
                    f"{reference.executable_path} -> "
                    f"{_python_environment_label(reference.interpreter_path)}"
                ),
                packages=packages,
            )
        )
    return sources


def discover_python_executables(
    path_value: str | None = None,
    *,
    home_only: bool = True,
) -> list[ExecutableReference]:
    references: list[ExecutableReference] = []
    home_root = Path.home().resolve()
    for directory in (path_value if path_value is not None else os.environ.get("PATH", "")).split(
        os.pathsep
    ):
        if not directory:
            continue
        dir_path = Path(directory)
        if not dir_path.is_dir():
            continue
        if home_only and not _is_under_home(dir_path, home_root):
            continue
        for candidate in sorted(dir_path.iterdir()):
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            interpreter = _shebang_python_interpreter(candidate)
            if interpreter is None:
                continue
            resolved_interpreter = _resolve_python_interpreter(interpreter)
            if resolved_interpreter is None:
                continue
            if home_only and not _is_under_home(resolved_interpreter, home_root):
                continue
            references.append(
                ExecutableReference(
                    executable_path=candidate,
                    interpreter_path=resolved_interpreter,
                )
            )
    return references


def _is_under_home(path: Path, home_root: Path) -> bool:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(home_root)
    except ValueError:
        return False
    return True


def _shebang_python_interpreter(executable_path: Path) -> Path | None:
    try:
        with executable_path.open("rb") as stream:
            shebang = stream.readline(512)
    except OSError:
        return None
    if not shebang.startswith(b"#!"):
        return None
    body = shebang[2:].decode("utf-8", errors="ignore").strip()
    if not body:
        return None
    tokens = shlex.split(body)
    if not tokens:
        return None
    if Path(tokens[0]).name == "env":
        tokens = tokens[1:]
        if tokens[:1] == ["-S"]:
            tokens = tokens[1:]
        if not tokens:
            return None
    interpreter = tokens[0]
    if not _looks_like_python_interpreter(interpreter):
        return None
    return Path(interpreter)


def _looks_like_python_interpreter(interpreter: str) -> bool:
    name = Path(interpreter).name.lower()
    return name.startswith("python") or name.startswith("pypy")


def _resolve_python_interpreter(interpreter: Path) -> Path | None:
    if interpreter.is_absolute() or interpreter.parent != Path("."):
        resolved = interpreter.resolve(strict=False)
        if not resolved.exists() or not os.access(resolved, os.X_OK):
            return None
        return resolved
    resolved = which(str(interpreter))
    if resolved is None:
        return None
    resolved_path = Path(resolved).resolve(strict=False)
    if not resolved_path.exists() or not os.access(resolved_path, os.X_OK):
        return None
    return resolved_path


def _python_environment_label(python_executable: Path) -> Path:
    resolved = python_executable.resolve(strict=False)
    parent = resolved.parent
    if parent.name in {"bin", "Scripts"} and parent.parent != parent:
        return parent.parent
    return parent


def _load_packages_from_distributions(
    distributions: Iterable[importlib_metadata.Distribution],
) -> list[PackageRecord]:
    packages: list[PackageRecord] = []
    for distribution in distributions:
        name = distribution.metadata.get("Name")
        version = distribution.version
        if not name or not version:
            continue
        try:
            parsed_version = Version(version)
        except InvalidVersion as exc:
            raise ValueError(f"Invalid installed version: {name} {version!r}") from exc
        packages.append(PackageRecord(name=name, version=parsed_version))
    return packages


def parse_constraints(text: str) -> list[Requirement]:
    requirements: list[Requirement] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = re.sub(r"\s+#.*$", "", stripped)
        requirements.append(Requirement(stripped))
    return requirements


def find_violations(
    packages: Sequence[PackageRecord],
    requirements: Sequence[Requirement],
    source_label: str = "",
) -> list[Violation]:
    violations: list[Violation] = []
    by_name = {}
    for package in packages:
        by_name.setdefault(canonicalize_name(package.name), []).append(package)

    for requirement in requirements:
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        matched_packages = by_name.get(canonicalize_name(requirement.name), [])
        for package in matched_packages:
            if requirement.specifier and not requirement.specifier.contains(
                package.version,
                prereleases=True,
            ):
                violations.append(
                    Violation(
                        source_label=source_label,
                        package_name=package.name,
                        package_version=package.version,
                        constraint=str(requirement),
                    )
                )
    return violations


def find_violations_for_source(
    source: PackageSource,
    requirements: Sequence[Requirement],
) -> list[Violation]:
    return find_violations(source.packages, requirements, source.label)


def find_violations_for_sources(
    sources: Sequence[PackageSource],
    requirements: Sequence[Requirement],
) -> list[Violation]:
    violations: list[Violation] = []
    for source in sources:
        violations.extend(find_violations_for_source(source, requirements))
    return violations


def format_violations(violations: Sequence[Violation]) -> str:
    lines = ["Found packages that do not satisfy security constraints:"]
    for violation in violations:
        lines.append(
            f"- [{violation.source_label}] {violation.package_name} {violation.package_version} does not satisfy {violation.constraint}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args, passthrough_args = parse_args(argv)

    try:
        command = resolve_constraints_command(args.constraints_command)
        constraints_text = fetch_constraints(command, passthrough_args)
        requirements = parse_constraints(constraints_text)
        if args.command == "lockfile":
            lockfile = Path(args.path)
            if not lockfile.exists():
                print(f"Lockfile not found: {lockfile}", file=sys.stderr)
                return 2
            sources = [load_lockfile_source(lockfile)]
            source_label = f"uv.lock ({lockfile})"
        elif args.command == "installed":
            sources = [load_installed_source(args.python)]
            source_label = "installed packages"
        elif args.command == "executables":
            sources = load_executable_sources(home_only=not args.all_executables)
            source_label = "executables"
            if not sources:
                print("No Python executables found on PATH.", file=sys.stderr)
                return 2
        else:
            raise ValueError(f"Unknown command: {args.command}")
        violations = find_violations_for_sources(sources, requirements)
        for source in sources:
            print(f"Checking {source.label}")
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() if exc.stderr else str(exc)
        print(message, file=sys.stderr)
        return 2
    except (ValueError, InvalidRequirement) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if violations:
        print(format_violations(violations))
        return 1

    print(f"No vulnerable packages found in {source_label}.")
    return 0
