# ELF deps

Python implementation of RPM [`elfdeps`](https://github.com/rpm-software-management/rpm/blob/master/tools/elfdeps.c). The `elfdeps` tool can extract dependencies and provides from an ELF binary.

## Example

```shell-session
$ elfdeps --requires /usr/bin/python3.12
libc.so.6(GLIBC_2.34)(64bit)
libc.so.6(GLIBC_2.2.5)(64bit)
libpython3.12.so.1.0()(64bit)
libc.so.6()(64bit)
rtld(GNU_HASH)

$ elfdeps --provides /usr/lib64/libpython3.12.so
libpython3.12.so.1.0()(64bit)
```

```shell-session
$ elfdeps --provides /lib64/libc.so.6
libc.so.6(GLIBC_2.2.5)(64bit)
libc.so.6(GLIBC_2.2.6)(64bit)
libc.so.6(GLIBC_2.3)(64bit)
...
libc.so.6(GLIBC_2.36)(64bit)
libc.so.6(GLIBC_2.38)(64bit)
libc.so.6(GLIBC_ABI_DT_RELR)(64bit)
libc.so.6(GLIBC_PRIVATE)(64bit)
libc.so.6()(64bit)
```

## RPM

In Fedora-based distributions, RPM packages provide and require virtual packages with ELF sonames and versions. The package manager can install virtual provides.

The `python3` base package depends on `libpython3.12.so.1.0()(64bit)` and `libc.so.6(GLIBC_2.34)(64bit)`:

```shell-session
$ rpm -qR python3
libc.so.6()(64bit)
libc.so.6(GLIBC_2.2.5)(64bit)
libc.so.6(GLIBC_2.34)(64bit)
libpython3.12.so.1.0()(64bit)
...
rtld(GNU_HASH)
```

The `python3-libs` package virtually provides `libpython3.12.so.1.0()(64bit)`:

```shell-session
$ rpm -qP python3-libs
bundled(libb2) = 0.98.1
libpython3.12.so.1.0()(64bit)
libpython3.so()(64bit)
python-libs = 3.12.3-2.fc39
python3-libs = 3.12.3-2.fc39
python3-libs(x86-64) = 3.12.3-2.fc39
python3.12-libs = 3.12.3-2.fc39
```

```shell-session
$ sudo dnf install 'libc.so.6(GLIBC_2.34)(64bit)' 'libpython3.12.so.1.0()(64bit)'
Package glibc-2.38-18.fc39.x86_64 is already installed.
Package python3-libs-3.12.3-2.fc39.x86_64 is already installed.
Dependencies resolved.
Nothing to do.
Complete!
```

## Public API

* dataclass `elfdeps.ELFAnalyzeSettings`
* exception `elfdeps.ELFError`
* dataclass `elfdeps.ELFInfo`
* dataclass `elfdeps.SOInfo`
* `elfdeps.analyze_dirtree(dirname, settings=None) -> Generator[ELFInfo, None, None]`
* `elfdeps.analyze_elffile(elffile, *, filename, is_exec, settings=None) -> ELFInfo`
* `elfdeps.analyze_file(filename, *, settings=None) -> ELFInfo`
* `elfdeps.analyze_tarfile(tfile, *, settings=None) -> Generator[ELFInfo, None, None]`
* `elfdeps.analyze_tarmember(tfile, tarinfo, *, settings=None) -> ELFInfo`
* `elfdeps.analyze_zipfile(zfile, *, settings=None) -> Generator[ELFInfo, None, None]`
* `elfdeps.analyze_zipmember(zfile, zipinfo, *, settings=None) -> ELFInfo`
