from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from uv_constraints_check.cli import (
    find_violations,
    load_lock_packages,
    parse_constraints,
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

    def test_find_violations_detects_matching_package(self) -> None:
        packages = load_lock_packages(self.write_lockfile())
        requirements = parse_constraints("demo<2\n")

        violations = find_violations(packages, requirements)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].package_name, "demo")

    def test_main_returns_failure_when_violation_is_found(self) -> None:
        lockfile = self.write_lockfile()

        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo<2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ):
            exit_code = main([str(lockfile)])

        self.assertEqual(exit_code, 1)

    def test_main_returns_error_when_lockfile_is_missing(self) -> None:
        with patch(
            "uv_constraints_check.cli.fetch_constraints",
            return_value="demo<2\n",
        ), patch(
            "uv_constraints_check.cli.resolve_constraints_command",
            return_value="security-constraints",
        ):
            exit_code = main(["missing-uv.lock"])

        self.assertEqual(exit_code, 2)

    def test_resolve_constraints_command_rejects_misspelling(self) -> None:
        with self.assertRaises(ValueError):
            resolve_constraints_command("secirity-constraints")

    def write_lockfile(self) -> Path:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        path = Path(tempdir.name) / "uv.lock"
        path.write_text(LOCKFILE_TEXT, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
