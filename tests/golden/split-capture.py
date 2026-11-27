#!/usr/bin/env python3
"""A zdb capture of a whole pool, one file a dataset.

    split-capture.py CAPTURE DIR

`zdb -dddddd` of a pool is one section a dataset, each opened by a line
`Dataset <name> [<type>], ...`, after whatever zdb printed before the
first (the metaslabs and their space maps). DIR gets one file a section,
numbered in zdb's order — `0000-head.txt`, then `0001-mos.txt`,
`0002-golden_fs-largednode@s4.txt`, … with `/` written as `_` — so that
the files read back in the order of their names are the capture again,
and each stays under the 50 MiB at which GitHub warns of a file in git.
The damage matrix reads the directory as the one capture
(`run-matrix.py`). A section still past that is an error: one file a
dataset is as far as the split goes, and git would refuse it.

This only cuts what zdb wrote; it reads nothing of a pool.
"""
import os
import re
import sys

LIMIT = 50 << 20
HEAD = re.compile(rb"^Dataset (\S+) \[", re.M)


def split(data):
    """[(name, bytes)]: what comes before the first section as `head`,
    then every section, whose bytes put together are `data` again.

    >>> split(b"ms\\nDataset mos [META], x\\n a\\nDataset p/q@s [ZPL], y\\n b\\n")
    [('head', b'ms\\n'), ('mos', b'Dataset mos [META], x\\n a\\n'), ('p_q@s', b'Dataset p/q@s [ZPL], y\\n b\\n')]
    >>> split(b"Dataset mos [META]\\n")
    [('mos', b'Dataset mos [META]\\n')]
    >>> split(b"nothing\\n")
    [('head', b'nothing\\n')]
    """
    starts = [(m.start(), m.group(1).decode("utf-8", "replace")) for m in HEAD.finditer(data)]
    out = []
    first = starts[0][0] if starts else len(data)
    if first > 0:
        out.append(("head", data[:first]))
    for i, (at, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(data)
        out.append((name.replace("/", "_"), data[at:end]))
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 1
    data = open(argv[0], "rb").read()
    parts = split(data)
    too_large = [(name, len(chunk)) for name, chunk in parts if len(chunk) >= LIMIT]
    if too_large:
        for name, n in too_large:
            print(f"split-capture: {name} is {n >> 20} MiB, past the {LIMIT >> 20} MiB a file in git should stay under",
                  file=sys.stderr)
        return 1
    os.makedirs(argv[1], exist_ok=True)
    for i, (name, chunk) in enumerate(parts):
        with open(os.path.join(argv[1], f"{i:04d}-{name}.txt"), "wb") as f:
            f.write(chunk)
    largest = max(parts, key=lambda p: len(p[1]))
    print(f"split-capture: {len(data) >> 20} MiB in {len(parts)} files, the largest {largest[0]} "
          f"({len(largest[1]) >> 20} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
