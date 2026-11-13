from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANGELOG = _REPO_ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _REPO_ROOT / "docs" / "release-notes.md"


def unreleased_entries(text: str) -> list[str]:
    section = text.split("\nUnreleased\n", 1)[1].split("\n___\n", 1)[0]
    return [line for line in section.splitlines() if line.startswith("- **")]


def _entries() -> tuple[list[str], list[str]]:
    return (
        unreleased_entries(_CHANGELOG.read_text(encoding="utf-8")),
        unreleased_entries(_RELEASE_NOTES.read_text(encoding="utf-8")),
    )


def test_every_changelog_entry_has_an_identical_twin_in_the_release_notes() -> None:
    changelog, release_notes = _entries()
    assert changelog, "CHANGELOG.md Unreleased section has no entries"
    assert [line for line in changelog if line not in release_notes] == []


def test_the_release_notes_hold_nothing_the_changelog_lacks() -> None:
    changelog, release_notes = _entries()
    assert [line for line in release_notes if line not in changelog] == []


def test_the_parity_check_fails_when_one_entry_is_removed_from_one_file() -> None:
    changelog, release_notes = _entries()
    first_marked = next(line for line in release_notes if line in changelog)
    trimmed = [line for line in release_notes if line != first_marked]
    assert [line for line in changelog if line not in trimmed] != []
