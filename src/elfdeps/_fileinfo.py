# SPDX-License-Identifier: Apache-2.0
"""File prefix and suffix"""

import importlib.machinery
import pathlib
import re
import stat

# platlib extension suffixes
EXTENSION_SUFFIXES = tuple(importlib.machinery.EXTENSION_SUFFIXES)
# Python-only suffix
PYTHON_EXTENSION_SUFFIXES = tuple(es for es in EXTENSION_SUFFIXES if es != ".so")
# dynamic linker prefix
LD_PREFIX: tuple[str, ...] = ("ld.", "ld-", "ld64.", "ld64-")
# pattern for libname.so / libname.so.1.2.3
LIB_RE = re.compile(
    r"^"
    # library or dynamic linker prefix
    r"(?P<prefix>lib|ld(?:64)?[.-])"
    # name starts with an alphanumic character
    r"(?P<name>\w.*)"
    r"\.so"
    # optional SOVERSION
    r"(?:\.(?P<version>[\d.]+))?"
    r"$"
)


def is_so_candidate(filename: pathlib.Path) -> bool:
    """Does the filename look like a a shared object?

    - Python shared extension with EXTENSION_SUFFIX, e.g.
      `name.cpython-312-x86_64-linux-gnu.so`, `name.abi3.so`, or
      `name.so`
    - unversioned shared library, e.g. `libfoo.so`
    - versioned shared library, e.g. `libfoo.so.1.2.3`
    - dynamic linker, e.g. `ld-linux-x86-64.so.2`
    """
    name: str = filename.name
    if name.endswith(EXTENSION_SUFFIXES):
        # Python extension
        return True
    # lib*.so, lib*.so.1.2.3, dynamic linker
    mo = LIB_RE.match(name)
    return mo is not None


_ix = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def is_executable_file(mode: int) -> bool:
    """Is mode for an executable file (no symlink)?"""
    if not stat.S_ISREG(mode):
        return False
    return bool(stat.S_IMODE(mode) & _ix)
