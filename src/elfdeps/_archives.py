# SPDX-License-Identifier: Apache-2.0
"""Analyze archive members"""

import pathlib
import stat
import tarfile
import typing
import zipfile

from elftools.elf.elffile import ELFFile

from ._elfdeps import ELFAnalyzeSettings, ELFInfo, analyze_elffile


def analyze_zipmember(
    zfile: zipfile.ZipFile,
    zipinfo: zipfile.ZipInfo,
    *,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analyze a zipfile member"""
    mode = zipinfo.external_attr >> 16
    is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    filename = pathlib.Path(zipinfo.filename)
    with zfile.open(zipinfo, mode="r") as f:
        elffile = ELFFile(f)
        return analyze_elffile(
            elffile, filename=filename, is_exec=is_exec, settings=settings
        )


def analyze_tarmember(
    tfile: tarfile.TarFile,
    tarinfo: tarfile.TarInfo,
    *,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analze a tarfile member"""
    mode = tarinfo.mode
    is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    filename = pathlib.Path(tarinfo.name)
    f = tfile.extractfile(tarinfo)
    if typing.TYPE_CHECKING:
        assert f is not None
    with f:
        elffile = ELFFile(f)
        return analyze_elffile(
            elffile, filename=filename, is_exec=is_exec, settings=settings
        )
