from __future__ import annotations

import argparse
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


@dataclass(frozen=True)
class LockPackage:
    name: str
    version: Version


@dataclass(frozen=True)
class Violation:
    package_name: str
    package_version: Version
    constraint: str


def parse_args(argv: Sequence[str] | None = None) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        prog="uv-constraints-check",
        description="Check uv.lock against constraints from security-constraints.",
    )
    parser.add_argument(
        "lockfile",
        nargs="?",
        default="uv.lock",
        help="Path to uv.lock. Defaults to ./uv.lock.",
    )
    parser.add_argument(
        "--constraints-command",
        default="",
        help="Override the security-constraints executable name.",
    )
    return parser.parse_known_args(argv)


def resolve_constraints_command(explicit_command: str) -> str:
    command = explicit_command or DEFAULT_CONSTRAINT_COMMAND
    if command != DEFAULT_CONSTRAINT_COMMAND:
        raise ValueError(
            "Only the correct executable name 'security-constraints' is accepted."
        )
    if which(command) is None:
        raise FileNotFoundError(f"Could not find {DEFAULT_CONSTRAINT_COMMAND} in PATH.")
    return command


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


def load_lock_packages(lockfile: Path) -> list[LockPackage]:
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    packages: list[LockPackage] = []
    for entry in data.get("package", []):
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        try:
            parsed_version = Version(version)
        except InvalidVersion as exc:
            raise ValueError(f"Invalid version in {lockfile}: {name} {version!r}") from exc
        packages.append(LockPackage(name=name, version=parsed_version))
    return packages


def parse_constraints(text: str) -> list[Requirement]:
    requirements: list[Requirement] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirements.append(Requirement(stripped))
    return requirements


def find_violations(packages: Sequence[LockPackage], requirements: Sequence[Requirement]) -> list[Violation]:
    violations: list[Violation] = []
    by_name = {}
    for package in packages:
        by_name.setdefault(canonicalize_name(package.name), []).append(package)

    for requirement in requirements:
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        matched_packages = by_name.get(canonicalize_name(requirement.name), [])
        for package in matched_packages:
            if requirement.specifier and requirement.specifier.contains(
                package.version,
                prereleases=True,
            ):
                violations.append(
                    Violation(
                        package_name=package.name,
                        package_version=package.version,
                        constraint=str(requirement),
                    )
                )
    return violations


def format_violations(violations: Sequence[Violation]) -> str:
    lines = ["Found vulnerable packages in uv.lock:"]
    for violation in violations:
        lines.append(
            f"- {violation.package_name} {violation.package_version} matches {violation.constraint}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args, passthrough_args = parse_args(argv)
    lockfile = Path(args.lockfile)
    if not lockfile.exists():
        print(f"Lockfile not found: {lockfile}", file=sys.stderr)
        return 2

    try:
        command = resolve_constraints_command(args.constraints_command)
        constraints_text = fetch_constraints(command, passthrough_args)
        requirements = parse_constraints(constraints_text)
        packages = load_lock_packages(lockfile)
        violations = find_violations(packages, requirements)
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

    print("No vulnerable packages found in uv.lock.")
    return 0
