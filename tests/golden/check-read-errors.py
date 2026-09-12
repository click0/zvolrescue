#!/usr/bin/env python3
"""Every way a read can fail is classified by the damage matrix.

`run-matrix.py` decides whether a failed block is the tool answering
damage honestly or the tool breaking, and it decides it from the text the
error prints. That list was written by hand once and then drifted: when a
pool lost a whole top-level vdev, the honest `DVA names unknown top-level
vdev 0` was not on it, and six correct results were recorded as defects.

So the list is held against the enum. Every `ReadError` variant must be
either matched by a clean reason or named as deliberately unclean; a new
variant fails here, on a branch, rather than turning honest failures into
breakage in a matrix run nobody reruns for months.

    check-read-errors.py [crates/zfs-read/src/zio.rs]
"""

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def matrix():
    spec = importlib.util.spec_from_file_location("m", os.path.join(HERE, "run-matrix.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def variants(source):
    """{variant: format string} from the `Display` impl of `ReadError`."""
    body = re.search(r"impl fmt::Display for ReadError.*?\n\}\n", source, re.S)
    if not body:
        raise SystemExit("zio.rs: no Display impl for ReadError")
    out = {}
    for m in re.finditer(r"ReadError::(\w+)(?:\([^)]*\))?\s*=>\s*write!\(f,\s*\"([^\"]*)\"", body.group(0)):
        out[m.group(1)] = m.group(2)
    if not out:
        raise SystemExit("zio.rs: no variants found in the Display impl")
    return out


def main(argv):
    path = argv[1] if len(argv) > 1 else os.path.join(HERE, "..", "..", "crates", "zfs-read", "src", "zio.rs")
    mod = matrix()
    found = variants(open(path, encoding="utf-8").read())
    # The matrix matches its reasons anywhere in the printed line, so the
    # check has to ask the same question: does some reason appear in what
    # this variant prints? Matching only the text before the first
    # placeholder missed `top-level vdev type {k} not supported yet`,
    # where the words that classify it come after the placeholder.
    unclassified = []
    for name, fmt in sorted(found.items()):
        if name in mod.UNCLEAN_VARIANTS:
            continue
        if any(r in fmt for r in mod.CLEAN_REASONS):
            continue
        # A wrapper — `gang block: {e}` — carries no words of its own:
        # what classifies it is the error inside, so it counts as
        # classified when some reason begins with its prefix.
        prefix = fmt.split("{")[0]
        if prefix and any(r.startswith(prefix) for r in mod.CLEAN_REASONS):
            continue
        unclassified.append(f"{name}: prints {fmt!r}")
    print(f"{len(found)} ReadError variant(s); {len(mod.CLEAN_REASONS)} clean reason(s); "
          f"{len(mod.UNCLEAN_VARIANTS)} deliberately unclean")
    if unclassified:
        print("\nnot classified by the damage matrix:", file=sys.stderr)
        for u in unclassified:
            print("  " + u, file=sys.stderr)
        print("\nAdd it to CLEAN_REASONS in run-matrix.py if the tool is answering\n"
              "damage honestly there, or to UNCLEAN_VARIANTS if reaching it means\n"
              "the reader broke.", file=sys.stderr)
        return 1
    # A reason nobody prints any more is dead weight that hides drift.
    # `gang block: …` is the exception: the wrapper prints the inner
    # error, whose text lives elsewhere in the file.
    stale = [r for r in mod.CLEAN_REASONS
             if not r.startswith("gang block:")
             and not any(r in f for f in found.values())]
    if stale:
        print("\nclean reasons no ReadError prints any more:", file=sys.stderr)
        for s in stale:
            print("  " + repr(s), file=sys.stderr)
        return 1
    print("every variant is classified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
