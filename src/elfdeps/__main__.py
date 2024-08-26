# SPDX-License-Identifier: Apache-2.0

import argparse
import logging
import pathlib
import pprint
import stat
import tarfile
import zipfile

from . import _archives, _elfdeps

ZIPEXT = (".zip", ".whl")
TAREXT = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")

parser = argparse.ArgumentParser("elfdeps")
parser.add_argument("filename", type=pathlib.Path)
parser.add_argument(
    "-d",
    "--debug",
    action="store_true",
    dest="debug",
    help="debug logging",
)
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
parser.add_argument(
    "--unique",
    "-u",
    action="store_true",
    dest="unique",
    help="Remove duplicate entries",
)


def main(argv: list[str] | None = None) -> None:
    args = parser.parse_args(argv)
    settings = _elfdeps.ELFAnalyzeSettings(
        soname_only=args.soname_only,
        fake_soname=args.fake_soname,
        filter_soname=args.filter_soname,
        require_interp=args.require_interp,
        unique=args.unique,
    )
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    filename: pathlib.Path = args.filename
    st = filename.stat()
    if filename.name.endswith(ZIPEXT):
        with zipfile.ZipFile(filename, mode="r") as zfile:
            infos = list(_archives.analyze_zipfile(zfile=zfile, settings=settings))
    elif filename.name.endswith(TAREXT):
        with tarfile.TarFile.open(filename, mode="r:*") as tfile:
            infos = list(_archives.analyze_tarfile(tfile=tfile, settings=settings))
    elif stat.S_ISDIR(st.st_mode):
        infos = list(_archives.analyze_dirtree(filename, settings=settings))
    else:
        infos = [_elfdeps.analyze_file(filename, settings=settings)]

    if args.provides:
        provides = set()
        for info in infos:
            provides.update(info.provides)
        for p in sorted(provides):
            print(p)
    elif args.requires:
        requires = set()
        for info in infos:
            requires.update(info.requires)
        for r in sorted(requires):
            print(r)
    else:
        for info in sorted(infos):
            pprint.pprint(info)


if __name__ == "__main__":
    main()
