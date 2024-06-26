# SPDX-License-Identifier: Apache-2.0

import argparse
import pathlib
import pprint

from ._elfdeps import ELFDeps

parser = argparse.ArgumentParser("elfdeps")
parser.add_argument("filename", type=pathlib.Path)
parser.add_argument(
    "-P",
    "--provides",
    action="store_true",
    dest="provides",
    help="Print ELF provides",
)
parser.add_argument(
    "-R",
    "--requires",
    action="store_true",
    dest="requires",
    help="Print ELF requires",
)
parser.add_argument(
    "--soname-only",
    action="store_true",
    dest="soname_only",
    help="Print shared object names only (exclude versions)",
)
parser.add_argument(
    "--no-fake-soname",
    action="store_false",
    dest="fake_soname",
    help="Don't include fake shared object names",
)
parser.add_argument(
    "--no-filter-soname",
    action="store_false",
    dest="filter_soname",
    help="Do not filter (default: exclude files that do not match 'lib*.so*')",
)
parser.add_argument(
    "--require-interp",
    action="store_true",
    dest="require_interp",
    help="Include ELF interpreter name",
)


def main(argv=None):
    args = parser.parse_args(argv)
    e = ELFDeps(
        args.filename,
        soname_only=args.soname_only,
        fake_soname=args.fake_soname,
        filter_soname=args.filter_soname,
        require_interp=args.require_interp,
    )
    if args.provides:
        for p in e.info.provides:
            print(p)
    if args.requires:
        for r in e.info.requires:
            print(r)
    if not args.requires and not args.provides:
        pprint.pprint(e.info)


if __name__ == "__main__":
    main()
