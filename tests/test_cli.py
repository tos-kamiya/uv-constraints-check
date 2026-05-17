from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from uv_constraints_check.cli import (
    ExecutableReference,
    PackageSource,
    discover_python_executables,
    find_violations,
    load_installed_packages,
    load_executable_sources,
    load_lock_packages,
    parse_constraints,
    parse_args,
    main,
    resolve_constraints_command,
)


LOCKFILE_TEXT = """\
version = 1
revision = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
"""


class CliTests(unittest.TestCase):
    def test_parse_constraints_skips_blank_and_comment_lines(self) -> None:
        requirements = parse_constraints(
            """
            # comment
            demo<2
            """
        )
        self.assertEqual(len(requirements), 1)
        self.assertEqual(str(requirements[0]), "demo<2")

    def test_parse_constraints_strips_inline_comments(self) -> None:
        requirements = parse_constraints(
            "APKLeaks>=2.0.4  # CVE-2021-21386 (ID: GHSA-8434-v7xw-8m9x)\n"
        )
        self.assertEqual(len(requirements), 1)
        self.assertEqual(str(requirements[0]), "APKLeaks>=2.0.4")

    def test_find_violations_detects_package_outside_constraint(self) -> None:
        packages = load_lock_packages(self.write_lockfile())
        requirements = parse_constraints("demo>=2\n")

        violations = find_violations(packages, requirements)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].package_name, "demo")

    def test_find_violations_ignores_package_that_satisfies_constraint(self) -> None:
        packages = load_lock_packages(self.write_lockfile())
        requirements = parse_constraints("demo>=1.0\n")

        violations = find_violations(packages, requirements)

        self.assertEqual(violations, [])

    def test_main_returns_failure_when_violation_is_found(self) -> None:
        lockfile = self.write_lockfile()

        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo>=2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ):
            exit_code = main(["lockfile", str(lockfile)])

        self.assertEqual(exit_code, 1)

    def test_main_returns_error_when_lockfile_is_missing(self) -> None:
        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo<2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ):
            exit_code = main(["lockfile", "missing-uv.lock"])

        self.assertEqual(exit_code, 2)

    def test_resolve_constraints_command_rejects_misspelling(self) -> None:
        with self.assertRaises(ValueError):
            resolve_constraints_command("secirity-constraints")

    def test_main_can_check_installed_packages(self) -> None:
        packages = load_lock_packages(self.write_lockfile())

        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo>=2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ), patch(
            "uv_constraints_check.cli.load_installed_packages",
            return_value=packages,
        ):
            exit_code = main(["installed"])

        self.assertEqual(exit_code, 1)

    def test_main_can_check_executables(self) -> None:
        packages = load_lock_packages(self.write_lockfile())

        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo>=2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ), patch(
            "uv_constraints_check.cli.load_executable_sources",
            return_value=[PackageSource(label="/tmp/zstarview -> /tmp/python3", packages=packages)],
        ):
            exit_code = main(["executables"])

        self.assertEqual(exit_code, 1)

    def test_parse_args_requires_target(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args([])

    def test_parse_args_rejects_python_without_installed(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["lockfile", "uv.lock", "--python", "/usr/bin/python3"])

    def test_parse_args_rejects_all_executables_without_executables(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["installed", "--all-executables"])

    def test_parse_args_accepts_constraints_command_after_subcommand(self) -> None:
        args, _ = parse_args(["lockfile", "uv.lock", "--constraints-command", "security-constraints"])
        self.assertEqual(args.constraints_command, "security-constraints")

    def test_discover_python_executables_finds_python_shebang(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        script_path = Path(tempdir.name) / "zstarview"
        script_path.write_text(f"#!{sys.executable}\nprint('ok')\n", encoding="utf-8")
        script_path.chmod(0o755)

        with patch.dict(
            "os.environ",
            {"PATH": tempdir.name},
            clear=False,
        ):
            references = discover_python_executables(home_only=False)

        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].executable_path, script_path)
        self.assertTrue(references[0].interpreter_path.name.startswith("python"))

    def test_discover_python_executables_keeps_multiple_scripts_for_same_interpreter(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        script_a = Path(tempdir.name) / "alpha"
        script_b = Path(tempdir.name) / "beta"
        shebang = f"#!{sys.executable}\nprint('ok')\n"
        script_a.write_text(shebang, encoding="utf-8")
        script_b.write_text(shebang, encoding="utf-8")
        script_a.chmod(0o755)
        script_b.chmod(0o755)

        with patch.dict(
            "os.environ",
            {"PATH": tempdir.name},
            clear=False,
        ):
            references = discover_python_executables(home_only=False)

        self.assertEqual({ref.executable_path for ref in references}, {script_a, script_b})

    def test_discover_python_executables_skips_outside_home_by_default(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        script_path = Path(tempdir.name) / "cb"
        script_path.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")
        script_path.chmod(0o755)

        with patch.dict(
            "os.environ",
            {"PATH": tempdir.name},
            clear=False,
        ), patch(
            "uv_constraints_check.cli._resolve_python_interpreter",
            return_value=Path("/usr/bin/python3.12"),
        ):
            references = discover_python_executables()

        self.assertEqual(references, [])

    def test_executables_default_skips_system_interpreters(self) -> None:
        with patch(
            "uv_constraints_check.cli.discover_python_executables",
            return_value=[
                ExecutableReference(
                    executable_path=Path("/home/toshihiro/bin/cb"),
                    interpreter_path=Path("/usr/bin/python3.12"),
                )
            ],
        ):
            sources = load_executable_sources()

        self.assertEqual(sources, [])

    def test_load_executable_sources_skips_missing_interpreters(self) -> None:
        with patch(
            "uv_constraints_check.cli.discover_python_executables",
            return_value=[
                ExecutableReference(
                    executable_path=Path("/tmp/zstarview"),
                    interpreter_path=Path("/usr/bin/python"),
                )
            ],
        ), patch(
            "uv_constraints_check.cli.load_installed_packages_from_python",
            side_effect=FileNotFoundError("Python executable not found: /usr/bin/python"),
        ):
            sources = load_executable_sources()

        self.assertEqual(sources, [])

    def test_load_installed_packages_uses_current_environment(self) -> None:
        class FakeDistribution:
            def __init__(self, name: str, version: str) -> None:
                self.metadata = {"Name": name}
                self.version = version

        with patch(
            "uv_constraints_check.cli.importlib_metadata.distributions",
            return_value=[
                FakeDistribution("demo", "1.2.3"),
            ],
        ):
            packages = load_installed_packages()

        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].name, "demo")

    def write_lockfile(self) -> Path:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        path = Path(tempdir.name) / "uv.lock"
        path.write_text(LOCKFILE_TEXT, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
