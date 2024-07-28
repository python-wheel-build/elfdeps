# SPDX-License-Identifier: Apache-2.0
"""elfdeps

Verbatim re-implementation of RPM's elfdeps

https://github.com/rpm-software-management/rpm/blob/master/tools/elfdeps.c
"""

import dataclasses
import os
import pathlib
import stat

from elftools.elf.constants import VER_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerDefSection, GNUVerNeedSection


@dataclasses.dataclass(frozen=True, order=True)
class SOInfo:
    """Shared object information

    soname: shared object name (e.g. ``libc.so.6``)
    version: symbol name (e.g. ``GLIBC_2.34``)
    marker: additional marker (empty or ``(64bit)``)
    """

    soname: str
    version: str
    marker: str

    def __str__(self) -> str:
        # libc.so.6(GLIBC_2.34)(64bit)
        # libc.so.6()(64bit)
        # rtld(GNU_HASH)
        return f"{self.soname}({self.version}){self.marker}"

    def __repr__(self) -> str:
        return str(self)


@dataclasses.dataclass
class ELFInfo:
    """ELF information

    filename: filename of analysed object
    requires: required shared object names
    provides: provided shared object names
    machine: ELF machine name (e.g. ``EM_X86_64``)
    is_dso: is file a ET_DYN (dynamic shared object)?
    is_exec: does file have the executable bit?
    got_debug: is dynamic tag DT_DEBUG set?
    got_hash: is dynamic tag DT_HASH set?
    got_gnuhash: is dynamic tag DT_GNUHASH set?
    soname: name from dynamic tag DT_SONAME
    interp: ELF interpreter name from PT_INTERP
    marker: marker name (empty or ``(64bit)``)
    runpath: DT_RUNPATH list from dynamic section
    """

    filename: pathlib.Path | None
    # requires and provides are ordered by occurence in ELF metadata and
    # can contain duplicate entries. The order can be different than output
    # of elfdeps.c, but that usually does not matter.
    requires: list[SOInfo]
    provides: list[SOInfo]
    machine: str | None = None
    is_dso: bool = False
    is_exec: bool = False
    got_debug: bool = False
    got_hash: bool = False
    got_gnuhash: bool = False
    soname: str | None = None
    interp: str | None = None
    marker: str = ""
    # useful extras
    runpath: list[str] | None = None


@dataclasses.dataclass(frozen=True)
class ELFAnalyzeSettings:
    """ELF analyze settings

    soname_only: exclude symbol version
    fake_soname: add fake soname from filename if DT_SONAME is missing
    filter_soname: exclude sonames that don't match 'lib*.so*'
    require_interp: add dependency on ELF interpreter
    unique: remove duplicates
    """

    soname_only: bool = False
    fake_soname: bool = True
    filter_soname: bool = False
    require_interp: bool = False
    unique: bool = True


def skip_soname(soname: str, *, filter_soname: bool = True) -> bool:
    """Rough soname sanity filtering

    soname: base name of shared library
    """
    # only basename
    assert os.pathsep not in soname
    # filter out empty or all-whitespace names
    if not soname.strip():
        return True
    if filter_soname:
        # must contain ".so"
        if ".so" not in soname:
            return True
        # dynamic linker
        if soname.startswith(("ld.", "ld-", "ld64.", "ld64-")):
            return False
        # must start with "lib"
        return not soname.startswith("lib")
    return False


def analyze_elffile(
    elffile: ELFFile,
    *,
    filename: pathlib.Path,
    is_exec: bool,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analyze an ELFFile object"""
    if settings is None:
        settings = ELFAnalyzeSettings()
    ed = _ELFDeps(elffile, filename=filename, is_exec=is_exec, settings=settings)
    return ed.process()


def analyze_file(
    filename: pathlib.Path,
    *,
    settings: ELFAnalyzeSettings | None = None,
) -> ELFInfo:
    """Analyze a file by path"""
    with filename.open("rb") as f:
        elffile = ELFFile(f)
        mode = os.fstat(f.fileno()).st_mode
        is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        return analyze_elffile(
            elffile, filename=filename, is_exec=is_exec, settings=settings
        )


class _ELFDeps:
    def __init__(
        self,
        elffile: ELFFile,
        *,
        filename: pathlib.Path,
        is_exec: bool,
        settings: ELFAnalyzeSettings,
    ) -> None:
        self.elffile = elffile
        assert isinstance(filename, pathlib.Path)
        self.info = ELFInfo(
            filename=filename,
            requires=[],
            provides=[],
            is_exec=is_exec,
        )
        self.settings: ELFAnalyzeSettings = settings
        self._seen: set[tuple[bool, SOInfo]] = set()

    def process(self) -> ELFInfo:
        """Process ELF file

        int processFile(const char *fn, int dtype)
        """
        ehdr = self.elffile.header
        if ehdr["e_type"] in {"ET_DYN", "ET_EXEC"}:
            self.info.machine = ehdr["e_machine"]
            self.info.marker = self.mkmarker()
            self.info.is_dso = ehdr["e_type"] == "ET_DYN"
            self.info.interp = self.process_prog_headers()
            self.process_sections()

        # For DSOs which use the .gnu_hash section and don't have a .hash
        # section, we need to ensure that we have a new enough glibc.
        if (
            self.gen_requires
            and self.info.got_gnuhash
            and not self.info.got_hash
            and not self.settings.soname_only
        ):
            # direct add
            self.info.requires.append(SOInfo("rtld", version="GNU_HASH", marker=""))

        # For DSOs, add DT_SONAME as provide.
        if self.info.is_dso and not self.info.got_debug:
            if (
                self.info.soname is None
                and self.settings.fake_soname
                and self.info.filename is not None
            ):
                self.info.soname = self.info.filename.name
            if self.info.soname:
                self.add_provides(self.info.soname)

        # If requested and present, add dep for interpreter (ie dynamic linker).
        if self.info.interp and self.settings.require_interp:
            # direct add
            self.info.requires.append(SOInfo(self.info.interp, version="", marker=""))
        return self.info

    def _add_soinfo(self, provides: bool, soname: str, version: str | None) -> None:
        if skip_soname(soname, filter_soname=self.settings.filter_soname):
            return
        version = version if version else ""
        marker = self.info.marker or ""
        soinfo = SOInfo(soname, version, marker)

        key = (provides, soinfo)
        if self.settings.unique and key in self._seen:
            return
        self._seen.add(key)

        if provides:
            self.info.provides.append(soinfo)
        else:
            self.info.requires.append(soinfo)

    def add_provides(self, soname: str, version: str | None = None) -> None:
        self._add_soinfo(True, soname, version)

    def add_requires(self, soname: str, version: str | None = None) -> None:
        self._add_soinfo(False, soname, version)

    @property
    def gen_requires(self) -> bool:
        """Generate requires?

        static int genRequires(elfInfo *ei)
        { return !(ei->interp && ei->isExec == 0); }
        """
        return not (self.info.interp and not self.info.is_exec)

    def mkmarker(self) -> str:
        """Get marker from EI_CLASS and e_machine

        const char *mkmarker(GElf_Ehdr *ehdr)
        """
        ehdr = self.elffile.header
        if ehdr["e_ident"]["EI_CLASS"] == "ELFCLASS64":
            if ehdr["e_machine"] in {"EM_ALPHA", "EM_FAKE_ALPHA"}:
                # alpha doesn't traditionally have 64bit markers
                return ""
            else:
                return "(64bit)"
        else:
            return ""

    def process_sections(self) -> None:
        """Process ELF sections

        Handles SHT_GNU_verdef, SHT_GNU_verneed, and SHT_DYNAMIC.

        void processSections(elfInfo *ei)
        """
        for sec in self.elffile.iter_sections():
            sh_type = sec.header["sh_type"]
            if sh_type == "SHT_GNU_verdef":
                self.process_verdef(sec)
            elif sh_type == "SHT_GNU_verneed":
                self.process_verneed(sec)
            elif sh_type == "SHT_DYNAMIC":
                self.process_dynamic(sec)

    def process_verdef(self, sec: GNUVerDefSection) -> None:
        """Process GNU version define section

        processVerDef(Elf_Scn *scn, GElf_Shdr *shdr, elfInfo *ei)
        """
        soname: str | None = None
        for verdef, vernaux in sec.iter_versions():
            for aux in vernaux:
                if not aux.name:
                    break
                # aux entry of verdef with VER_FLG_BASE is the soname
                if verdef["vd_flags"] & VER_FLAGS.VER_FLG_BASE:
                    soname = aux.name
                elif soname is not None and not self.settings.soname_only:
                    self.add_provides(soname, version=aux.name)

    def process_verneed(self, sec: GNUVerNeedSection) -> None:
        """Process GNU version need section

        void processVerNeed(Elf_Scn *scn, GElf_Shdr *shdr, elfInfo *ei)
        """
        for verneed, vernaux in sec.iter_versions():
            soname: str = verneed.name
            for aux in vernaux:
                if (
                    aux.name
                    and self.gen_requires
                    and soname
                    and not self.settings.soname_only
                ):
                    self.add_requires(soname, version=aux.name)

    def process_dynamic(self, sec: DynamicSection) -> None:
        """Process dynamic tags section

        Handles DT_HASH, DT_GNU_HASH, DT_DEBUG, DT_SONAME, and DT_NEEDED tags

        void processDynamic(Elf_Scn *scn, GElf_Shdr *shdr, elfInfo *ei)
        """
        for tag in sec.iter_tags():
            d_tag = tag.entry.d_tag
            if d_tag == "DT_HASH":
                self.info.got_hash = True
            elif d_tag == "DT_GNU_HASH":
                self.info.got_gnuhash = True
            elif d_tag == "DT_DEBUG":
                self.info.got_debug = True
            elif d_tag == "DT_SONAME":
                self.info.soname = tag.soname
            elif d_tag == "DT_NEEDED":
                self.add_requires(tag.needed)
            elif d_tag == "DT_RUNPATH":
                # library runpath, multiple values separated by ':'
                # $ORIGIN is kept unresolved
                self.info.runpath = tag.runpath.split(":")
            # DT_RPATH is deprecated

    def process_prog_headers(self) -> str | None:
        """Get interpreter from PT_INTERP segment

        void processProgHeaders(elfInfo *ei, GElf_Ehdr *ehdr)

        Example: `/lib64/ld-linux-x86-64.so.2`
        """
        for seg in self.elffile.iter_segments("PT_INTERP"):
            interp: str = seg.get_interp_name()
            if interp is not None:
                return interp
        else:
            return None
