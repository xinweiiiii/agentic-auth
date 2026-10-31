"""The release notes come from exactly one CHANGELOG section, or the release stops."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "changelog_section", ROOT / "scripts" / "changelog_section.py"
)
assert _spec and _spec.loader
changelog_section = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changelog_section)

TEXT = """# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-05

### Added

- Embedded mode.

## [0.1.1] - 2026-10-29

### Fixed

- A packaging bug.

[Unreleased]: https://example.invalid/compare/v0.2.0...HEAD
[0.2.0]: https://example.invalid/compare/v0.1.1...v0.2.0
"""


def test_a_middle_section_stops_at_the_next_heading() -> None:
    assert changelog_section.section(TEXT, "0.2.0") == "### Added\n\n- Embedded mode.\n"


def test_the_last_section_stops_at_the_link_references() -> None:
    assert changelog_section.section(TEXT, "0.1.1") == "### Fixed\n\n- A packaging bug.\n"


def test_a_missing_section_is_none_and_the_cli_fails(tmp_path) -> None:
    assert changelog_section.section(TEXT, "9.9.9") is None
    path = tmp_path / "CHANGELOG.md"
    path.write_text(TEXT)
    assert changelog_section.main(["--version", "9.9.9", "--changelog", str(path)]) == 1


def test_a_version_is_matched_literally() -> None:
    """`0.2.0` must not match a `0x2x0` heading through an unescaped dot."""
    assert changelog_section.section("## [0x2x0]\n\nnope\n", "0.2.0") is None


def test_the_real_changelog_has_its_released_sections() -> None:
    real = (ROOT / "CHANGELOG.md").read_text()
    assert changelog_section.section(real, "0.1.1")
    assert changelog_section.section(real, "0.1.0")
