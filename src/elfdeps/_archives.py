# SPDX-License-Identifier: Apache-2.0
"""Analyze archive members"""

import logging
import os
import pathlib
import stat
import tarfile
import typing
import zipfile

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from ._elfdeps import ELFAnalyzeSettings, ELFInfo, analyze_elffile
from ._fileinfo import is_executable_file

logger = logging.getLogger(__name__)


def _zipinfo_mode(zipinfo: zipfile.ZipInfo) -> int:
    """Full mode for zipinfo object"""
    # mode may not contain reg file info
    mode = zipinfo.external_attr >> 16
    if stat.S_IFMT(mode) == 0:
        lo = zipinfo.external_attr & 0xFFFF
        if lo & 0x10:
            # MS-DOS directory
            mode |= stat.S_IFDIR
        else:
            mode |= stat.S_IFREG
    return mode


def analyze_zipmember(
    zfile: zipfile.ZipFile,
    zipinfo: zipfile.ZipInfo,
    *,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analyze a zipfile member"""
    mode = _zipinfo_mode(zipinfo)
    is_exec = is_executable_file(mode)
    filename = pathlib.Path(zipinfo.filename)
    with zfile.open(zipinfo, mode="r") as f:
        elffile = ELFFile(f)
        return analyze_elffile(
            elffile, filename=filename, is_exec=is_exec, settings=settings
        )


def analyze_zipfile(
    zfile: zipfile.ZipFile, *, settings: ELFAnalyzeSettings | None = None
) -> typing.Generator[ELFInfo, None, None]:
    """Analyze a zip file"""
    if settings is None:
        settings = ELFAnalyzeSettings()
    for zipinfo in zfile.infolist():
        filename = pathlib.Path(zipinfo.filename)
        mode = _zipinfo_mode(zipinfo)
        if settings.is_candidate(filename, mode):
            try:
                yield analyze_zipmember(zfile, zipinfo, settings=settings)
            except ELFError as err:
                # not an ELF file (e.g. a script or linker script)
                logger.debug("%s is not a ELF file: %s", filename, err)


def _tarinfo_mode(tarinfo: tarfile.TarInfo) -> int:
    """Full mode for tarinfo"""
    # tarinfo.mode contains only permission bits
    mode = tarinfo.mode
    if tarinfo.isreg():
        mode |= stat.S_IFREG
    elif tarinfo.isdir():
        mode |= stat.S_IFDIR
    elif tarinfo.issym():
        mode |= stat.S_IFLNK
    elif tarinfo.isblk():
        mode |= stat.S_IFBLK
    elif tarinfo.ischr():
        mode |= stat.S_IFCHR
    elif tarinfo.isfifo():
        mode |= stat.S_IFIFO
    return mode


def analyze_tarmember(
    tfile: tarfile.TarFile,
    tarinfo: tarfile.TarInfo,
    *,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analze a tarfile member"""
    mode = _tarinfo_mode(tarinfo)
    is_exec = is_executable_file(mode)
    filename = pathlib.Path(tarinfo.name)
    f = tfile.extractfile(tarinfo)
    if typing.TYPE_CHECKING:
        assert f is not None
    with f:
        elffile = ELFFile(f)
        return analyze_elffile(
            elffile, filename=filename, is_exec=is_exec, settings=settings
        )


def analyze_tarfile(
    tfile: tarfile.TarFile, *, settings: ELFAnalyzeSettings | None = None
) -> typing.Generator[ELFInfo, None, None]:
    """Analyze a tar ball"""
    if settings is None:
        settings = ELFAnalyzeSettings()
    for tarinfo in tfile:
        filename = pathlib.Path(tarinfo.name)
        mode = _tarinfo_mode(tarinfo)
        if settings.is_candidate(filename, mode):
            try:
                yield analyze_tarmember(tfile, tarinfo, settings=settings)
            except ELFError as err:
                # not an ELF file (e.g. a script or linker script)
                logger.debug("%s is not a ELF file: %s", filename, err)


OnError = typing.Callable[[pathlib.Path, OSError | ELFError], None] | None


def _scanwalk(
    dirname: pathlib.Path, onerror: OnError = None
) -> typing.Generator[os.DirEntry, None, None]:
    """Recursive scandir"""
    try:
        it = os.scandir(dirname)
    except OSError as err:
        if onerror is not None:
            onerror(dirname, err)
        return

    with it:
        while True:
            try:
                entry = next(it)
            except StopIteration:
                break
            except OSError as err:
                if onerror is not None:
                    onerror(dirname, err)
                return
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir:
                yield from _scanwalk(pathlib.Path(entry.path), onerror=onerror)
            else:
                yield entry


def analyze_dirtree(
    dirname: pathlib.Path,
    *,
    settings: ELFAnalyzeSettings | None = None,
    onerror: OnError = None,
) -> typing.Generator[ELFInfo, None, None]:
    """Recursively analyze dirctory tree"""
    if settings is None:
        settings = ELFAnalyzeSettings()
    for entry in _scanwalk(dirname):
        filename = pathlib.Path(entry.path)
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
            if settings.is_candidate(filename, mode):
                with filename.open("rb") as f:
                    elffile = ELFFile(f)
                    yield analyze_elffile(
                        elffile,
                        filename=filename,
                        is_exec=is_executable_file(mode),
                        settings=settings,
                    )
        except (OSError, ELFError) as err:
            logger.debug("%s is not a ELF file or is not accessible: %s", filename, err)
            if onerror is not None:
                onerror(filename, err)
