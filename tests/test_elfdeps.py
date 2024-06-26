import sys
from pathlib import Path

import pytest

from elfdeps import ELFDeps


def test_python():
    e = ELFDeps(Path(sys.executable))
    assert e.info.requires


def test_libc():
    found = False
    for libdir in [Path("/lib"), Path("/lib64")]:
        libc = libdir / "libc.so.6"
        if libc.is_file():
            found = True
            e = ELFDeps(libc)
            assert e.info.provides

    if not found:
        pytest.skip("libc not found")
