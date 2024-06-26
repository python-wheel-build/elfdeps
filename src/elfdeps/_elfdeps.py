# SPDX-License-Identifier: Apache-2.0
"""elfdeps

Verbatim re-implementation of RPM's elfdeps

https://github.com/rpm-software-management/rpm/blob/master/tools/elfdeps.c
"""

import dataclasses
import io
import os
import pathlib
import stat

from elftools.elf.constants import VER_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerDefSection, GNUVerNeedSection


@dataclasses.dataclass(slots=True, frozen=True)
class SOInfo:
    """Shared object information"""

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


def skip_soname(soname: str, *, filter_soname: bool = True) -> bool:
    """Rough soname sanity filtering"""
    # only basename
    soname = pathlib.Path(soname).name
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


class ELFDeps:
    def __init__(
        self,
        filename: pathlib.Path,
        *,
        soname_only: bool = False,
        fake_soname: bool = True,
        filter_soname: bool = False,
        require_interp: bool = False,
    ) -> None:
        if not isinstance(filename, pathlib.Path):
            raise TypeError(f"filename is not a pathlib.Path: {type(filename)}")
        self.filename = filename
        self.soname_only = soname_only
        self.fake_soname = fake_soname
        self.filter_soname = filter_soname
        self.require_interp = require_interp

        self.info = ELFInfo(
            requires=[],
            provides=[],
        )
        with self.filename.open("rb") as f:
            self._process_file(f)

    def _process_file(self, f: io.BufferedReader) -> None:
        """Process ELF file

        int processFile(const char *fn, int dtype)
        """
        elffile = ELFFile(f)
        ehdr = elffile.header
        if ehdr["e_type"] in {"ET_DYN", "ET_EXEC"}:
            self.info.machine = ehdr["e_machine"]
            self.info.marker = self.mkmarker(elffile)
            self.info.is_dso = ehdr["e_type"] == "ET_DYN"
            mode = os.fstat(f.fileno()).st_mode
            self.info.is_exec = bool(
                mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            )

            self.info.interp = self.process_prog_headers(elffile)
            self.process_sections(elffile)

        # For DSOs which use the .gnu_hash section and don't have a .hash
        # section, we need to ensure that we have a new enough glibc.
        if (
            self.gen_requires
            and self.info.got_gnuhash
            and not self.info.got_hash
            and not self.soname_only
        ):
            # direct add
            self.info.requires.append(SOInfo("rtld", version="GNU_HASH", marker=""))

        # For DSOs, add DT_SONAME as provide.
        if self.info.is_dso and not self.info.got_debug:
            if self.info.soname is None and self.fake_soname:
                self.info.soname = self.filename.name
            if self.info.soname:
                self.add_provides(self.info.soname)

        # If requested and present, add dep for interpreter (ie dynamic linker).
        if self.info.interp and self.require_interp:
            # direct add
            self.info.requires.append(SOInfo(self.info.interp, version="", marker=""))

    def _add_soinfo(self, provides: bool, soname: str, version: str | None) -> bool:
        if skip_soname(soname, filter_soname=self.filter_soname):
            return False
        version = version if version else ""
        marker = self.info.marker or ""
        soinfo = SOInfo(soname, version, marker)
        if provides:
            self.info.provides.append(soinfo)
        else:
            self.info.requires.append(soinfo)
        return True

    def add_provides(self, soname: str, version: str | None = None) -> bool:
        return self._add_soinfo(True, soname, version)

    def add_requires(self, soname: str, version: str | None = None) -> bool:
        return self._add_soinfo(False, soname, version)

    @property
    def gen_requires(self) -> bool:
        """Generate requires?

        static int genRequires(elfInfo *ei)
        { return !(ei->interp && ei->isExec == 0); }
        """
        return not (self.info.interp and not self.info.is_exec)

    def mkmarker(self, elffile: ELFFile) -> str:
        """Get marker from EI_CLASS and e_machine

        const char *mkmarker(GElf_Ehdr *ehdr)
        """
        ehdr = elffile.header
        if ehdr["e_ident"]["EI_CLASS"] == "ELFCLASS64":
            if ehdr["e_machine"] in {"EM_ALPHA", "EM_FAKE_ALPHA"}:
                # alpha doesn't traditionally have 64bit markers
                return ""
            else:
                return "(64bit)"
        else:
            return ""

    def process_sections(self, elffile: ELFFile) -> None:
        """Process ELF sections

        Handles SHT_GNU_verdef, SHT_GNU_verneed, and SHT_DYNAMIC.

        void processSections(elfInfo *ei)
        """
        for sec in elffile.iter_sections():
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
                elif soname is not None and not self.soname_only:
                    self.add_provides(soname, version=aux.name)

    def process_verneed(self, sec: GNUVerNeedSection) -> None:
        """Process GNU version need section

        void processVerNeed(Elf_Scn *scn, GElf_Shdr *shdr, elfInfo *ei)
        """
        for verneed, vernaux in sec.iter_versions():
            soname: str = verneed.name
            for aux in vernaux:
                if aux.name and self.gen_requires and soname and not self.soname_only:
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

    def process_prog_headers(self, elffile: ELFFile) -> str | None:
        """Get interpreter from PT_INTERP segment

        void processProgHeaders(elfInfo *ei, GElf_Ehdr *ehdr)
        """
        for seg in elffile.iter_segments("PT_INTERP"):
            return seg.get_interp_name()
        else:
            return None
