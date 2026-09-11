#!/usr/bin/env python3
"""The part of the release notes that says what is in a release.

A tag here is made on the head of `main`, from the GitHub web interface,
which cannot tag an arbitrary commit. A version that was overtaken before
anyone tagged it therefore never becomes a release of its own — it ships
inside the next version that does get one. Notes that print only the
tagged version's own section then describe a fraction of what the
binaries carry, which is how `v0.7.0` came to be announced without five
of the things in it.

So: print the tagged version's section, then every older section down to
the first one that already has a release someone could have downloaded,
then whatever `## Unreleased` still held when the tag was made. What
comes out is everything these binaries are, and nothing that was
announced somewhere else.

    changelog-notes.py VERSION CHANGELOG.md RELEASED-TAGS-FILE
"""

import re
import sys

HEADING = re.compile(r"^## (?:v(?P<version>[0-9][^ ]*)|(?P<unreleased>Unreleased))\b")


def sections(text):
    """The changelog as `(version | None, heading, body)`, file order.

    `None` is the `Unreleased` section; anything that is not a version
    heading at all (the preamble) is dropped.
    """
    out = []
    current = None
    for line in text.split("\n"):
        m = HEADING.match(line)
        if m:
            current = (m.group("version"), line, [])
            out.append(current)
        elif line.startswith("## "):
            current = None
        elif current is not None:
            current[2].append(line)
    return out


def trimmed(body):
    """A body without the blank lines at either end."""
    body = list(body)
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return body


def demote(body, by=1):
    """Push every `###` heading `by` levels down, so a section carried
    under another heading reads as belonging to it."""
    return [("#" * by + line) if line.startswith("###") else line for line in body]


def notes(text, version, released):
    """The body of the notes for `version`.

    `released` is the set of tag names that already have a release.
    """
    found = sections(text)
    by_version = {v: i for i, (v, _, _) in enumerate(found) if v is not None}
    if version not in by_version:
        raise KeyError(version)
    at = by_version[version]
    body = trimmed(found[at][2])
    if not any(line.startswith("### ") for line in body):
        raise ValueError(f"the v{version} section has no '### ' heading")

    # Older versions, down to the first that was released on its own.
    carried = []
    for older_version, heading, older_body in found[at + 1 :]:
        if older_version is None:
            continue
        if f"v{older_version}" in released:
            break
        carried.append((older_version, heading, trimmed(older_body)))

    unreleased = next((trimmed(b) for v, _, b in found if v is None), [])

    out = list(body)
    if carried:
        first, last = carried[-1][0], carried[0][0]
        span = f"`v{first}`" if first == last else f"`v{first}` through `v{last}`"
        out += [
            "",
            "## Also in this release",
            "",
            f"{span} never had a release of its own — a tag here is made on"
            " the head of `main`, and these were overtaken before one was"
            " cut. This is where they ship.",
            "",
        ]
        for _, heading, older_body in carried:
            out += [heading.replace("## ", "### ", 1), ""] + demote(older_body) + [""]
    if any(line.startswith("* ") for line in unreleased):
        out += [
            "",
            "## Also in this tag, filed under no version yet",
            "",
        ] + demote(unreleased)
    return "\n".join(out).rstrip() + "\n"


def self_test():
    sample = """# Changelog

Preamble, which is not a section.

## Unreleased

### Fixed
* something not filed yet

## v0.3.0 — 2026-01-03

**Three.**

### Added
* the third thing

## v0.2.0 — 2026-01-02

**Two.**

### Added
* the second thing

## v0.1.0 — 2026-01-01

**One.**

### Added
* the first thing
"""
    # Nothing released yet below it: everything down to the bottom comes
    # along, newest first, and the span names both ends.
    out = notes(sample, "0.3.0", {"v0.3.0"})
    assert "**Three.**" in out
    assert "### v0.2.0 — 2026-01-02" in out and "### v0.1.0 — 2026-01-01" in out
    assert "`v0.1.0` through `v0.2.0` never had a release" in out, out
    # The carried sections' own headings went one level down, so they
    # read as belonging to the version carrying them.
    assert "#### Added\n* the second thing" in out, out
    assert "\n### Added\n* the third thing" in out, out

    # v0.2.0 released: the walk stops there and v0.1.0 stays with it.
    out = notes(sample, "0.3.0", {"v0.2.0"})
    assert "Also in this release" not in out, out
    assert "the second thing" not in out and "the first thing" not in out

    # One version carried reads as one version, not as a span.
    out = notes(sample, "0.3.0", {"v0.1.0"})
    assert "`v0.2.0` never had a release" in out, out
    assert "the first thing" not in out, out

    # Unreleased comes along whatever else does, and only when it holds
    # something.
    assert "something not filed yet" in notes(sample, "0.3.0", {"v0.2.0"})
    assert "Also in this tag" not in notes(sample.replace("* something not filed yet", ""), "0.3.0", {"v0.2.0"})

    # A version with no section, and one with no items, are refused
    # rather than published as an empty page.
    for bad, error in (("9.9.9", KeyError), ("0.0.0", KeyError)):
        try:
            notes(sample, bad, set())
        except error:
            pass
        else:
            raise AssertionError(f"{bad} should have been refused")
    try:
        notes(sample.replace("### Added\n* the third thing", "nothing here"), "0.3.0", set())
    except ValueError:
        pass
    else:
        raise AssertionError("a section with no '###' heading should have been refused")
    print("changelog-notes: self-test ok")


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        self_test()
        return 0
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    version, changelog, released_file = argv[1:]
    with open(changelog, encoding="utf-8") as f:
        text = f.read()
    with open(released_file, encoding="utf-8") as f:
        released = {line.strip() for line in f if line.strip()}
    try:
        sys.stdout.write(notes(text, version, released))
    except (KeyError, ValueError) as e:
        print(f"::error::{changelog}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
