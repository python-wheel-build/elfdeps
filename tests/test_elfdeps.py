import dataclasses
import pathlib
import sys
import sysconfig
import tarfile
import zipfile

import pytest

import elfdeps

SYMBOLS_SETTINGS = elfdeps.ELFAnalyzeSettings(include_symbols=True)


def test_python() -> None:
    info = elfdeps.analyze_file(pathlib.Path(sys.executable))
    assert info.requires


def test_zipmember_python(tmp_path: pathlib.Path):
    orig_info = elfdeps.analyze_file(pathlib.Path(sys.executable))
    zname = tmp_path / "test.zip"
    python = pathlib.Path(sys.executable).resolve()
    with zipfile.ZipFile(zname, mode="w") as zf:
        zf.write(python, "python")
        zf.write(__file__, "test.py")
    with zipfile.ZipFile(zname) as zf:
        zipinfo = zf.getinfo("python")
        info = elfdeps.analyze_zipmember(zf, zipinfo)
        assert info.requires == orig_info.requires
        assert info.provides == orig_info.provides

        infos = list(elfdeps.analyze_zipfile(zf))
        assert len(infos) == 1
        info = infos[0]
        assert info.requires == orig_info.requires
        assert info.provides == orig_info.provides


def test_tarmember_python(tmp_path: pathlib.Path):
    orig_info = elfdeps.analyze_file(pathlib.Path(sys.executable))
    tname = tmp_path / "test.tar.gz"
    python = pathlib.Path(sys.executable).resolve()
    with tarfile.TarFile.open(tname, mode="w:gz") as tf:
        tf.add(python, "python")
        tf.add(__file__, "test.py")
    with tarfile.TarFile.open(tname, mode="r:gz") as tf:
        tarinfo = tf.getmember("python")
        info = elfdeps.analyze_tarmember(tf, tarinfo)
        assert info.requires == orig_info.requires
        assert info.provides == orig_info.provides

        infos = list(elfdeps.analyze_tarfile(tf))
        assert len(infos) == 1
        info = infos[0]
        assert info.requires == orig_info.requires
        assert info.provides == orig_info.provides


def test_libc() -> None:
    found = False
    for libdir in [pathlib.Path("/lib64"), pathlib.Path("/lib")]:
        libc = libdir / "libc.so.6"
        if libc.is_file():
            found = True
            info = elfdeps.analyze_file(libc)
            assert info.provides

    if not found:
        pytest.skip("libc not found")


def test_symbols_default_none() -> None:
    """Symbols are None when include_symbols is False (default)."""
    info = elfdeps.analyze_file(pathlib.Path(sys.executable))
    assert info.exported_symbols is None
    assert info.imported_symbols is None


def test_symbols_python() -> None:
    """Python binary has imported symbols when include_symbols is True."""
    info = elfdeps.analyze_file(pathlib.Path(sys.executable), settings=SYMBOLS_SETTINGS)
    assert info.imported_symbols is not None
    assert info.exported_symbols is not None
    assert info.imported_symbols
    for sym in info.imported_symbols + info.exported_symbols:
        assert sym.name


def test_symbols_libc() -> None:
    """libc exports many versioned function and object symbols."""
    found = False
    for libdir in [pathlib.Path("/lib64"), pathlib.Path("/lib")]:
        libc = libdir / "libc.so.6"
        if libc.is_file():
            found = True
            info = elfdeps.analyze_file(libc, settings=SYMBOLS_SETTINGS)
            assert info.exported_symbols is not None
            assert len(info.exported_symbols) > 100
            versioned_funcs = [
                s
                for s in info.exported_symbols
                if s.type == elfdeps.SymbolType.FUNC and s.version
            ]
            assert versioned_funcs
            objects = [
                s for s in info.exported_symbols if s.type == elfdeps.SymbolType.OBJECT
            ]
            assert objects

    if not found:
        pytest.skip("libc not found")


def test_symbolinfo_frozen() -> None:
    """SymbolInfo is frozen and has slots."""
    sym = elfdeps.SymbolInfo(
        name="test",
        version="V1",
        binding=elfdeps.SymbolBinding.GLOBAL,
        type=elfdeps.SymbolType.FUNC,
    )
    assert sym.__slots__ == ("name", "version", "binding", "type")
    with pytest.raises(dataclasses.FrozenInstanceError):
        sym.name = "other"  # type: ignore[misc]


def test_symbolinfo_str() -> None:
    """SymbolInfo str format."""
    sym_versioned = elfdeps.SymbolInfo(
        name="printf",
        version="GLIBC_2.34",
        binding=elfdeps.SymbolBinding.GLOBAL,
        type=elfdeps.SymbolType.FUNC,
    )
    assert str(sym_versioned) == "printf@GLIBC_2.34"

    sym_plain = elfdeps.SymbolInfo(
        name="data_start",
        version=None,
        binding=elfdeps.SymbolBinding.WEAK,
        type=elfdeps.SymbolType.NOTYPE,
    )
    assert str(sym_plain) == "data_start"


def test_symbolinfo_ordering() -> None:
    """SymbolInfo supports ordering; binding is ignored."""
    a = elfdeps.SymbolInfo(
        "aaa", None, elfdeps.SymbolBinding.GLOBAL, elfdeps.SymbolType.FUNC
    )
    b = elfdeps.SymbolInfo(
        "bbb", None, elfdeps.SymbolBinding.WEAK, elfdeps.SymbolType.FUNC
    )
    assert a < b
    assert sorted([b, a]) == [a, b]
    # same name/version/type but different binding: equal and same hash
    g = elfdeps.SymbolInfo(
        "foo", "V1", elfdeps.SymbolBinding.GLOBAL, elfdeps.SymbolType.FUNC
    )
    w = elfdeps.SymbolInfo(
        "foo", "V1", elfdeps.SymbolBinding.WEAK, elfdeps.SymbolType.FUNC
    )
    assert g == w
    assert hash(g) == hash(w)
    assert {g, w} == {g}


def test_symbol_binding_enum() -> None:
    """SymbolBinding enum values."""
    assert elfdeps.SymbolBinding.GLOBAL.value == "global"
    assert elfdeps.SymbolBinding.WEAK.value == "weak"
    assert elfdeps.SymbolBinding("global") is elfdeps.SymbolBinding.GLOBAL


def test_symbol_type_enum() -> None:
    """SymbolType enum values."""
    assert elfdeps.SymbolType.FUNC.value == "func"
    assert elfdeps.SymbolType.OBJECT.value == "object"
    assert elfdeps.SymbolType.NOTYPE.value == "notype"
    assert elfdeps.SymbolType.TLS.value == "tls"
    assert elfdeps.SymbolType("func") is elfdeps.SymbolType.FUNC


def test_symbols_binding_types() -> None:
    """All extracted symbols have valid binding and type."""
    info = elfdeps.analyze_file(pathlib.Path(sys.executable), settings=SYMBOLS_SETTINGS)
    assert info.exported_symbols is not None
    assert info.imported_symbols is not None
    for sym in info.exported_symbols + info.imported_symbols:
        assert isinstance(sym.binding, elfdeps.SymbolBinding)
        assert isinstance(sym.type, elfdeps.SymbolType)


def test_symbols_libpython() -> None:
    """libpython imports libc allocators and exports stable ABI symbols."""
    instsoname = sysconfig.get_config_var("INSTSONAME")
    if instsoname is None:
        # static build, use the Python executable itself
        libpython = pathlib.Path(sys.executable)
    else:
        libdir = sysconfig.get_config_var("LIBDIR")
        libpython = pathlib.Path(libdir) / instsoname
        assert libpython.is_file(), f"{libpython} not found"
    info = elfdeps.analyze_file(libpython, settings=SYMBOLS_SETTINGS)
    assert info.exported_symbols is not None
    assert info.imported_symbols is not None
    exported = {s.name: s for s in info.exported_symbols}
    imported = {s.name: s for s in info.imported_symbols}
    # libc allocators are imported as global functions
    for name in ("malloc", "free"):
        sym = imported[name]
        assert sym.binding == elfdeps.SymbolBinding.GLOBAL
        assert sym.type == elfdeps.SymbolType.FUNC
    # stable ABI functions from https://docs.python.org/3/c-api/stable.html
    for name in (
        "PyList_Append",
        "PyTuple_New",
        "PyDict_SetItem",
        "PySet_Add",
        "PyBytes_AsString",
        "PyUnicode_FromString",
        "PyLong_AsLong",
        "PyFloat_FromDouble",
        "PyErr_SetString",
        "PyObject_GetAttr",
        "PyType_Ready",
        "PyGILState_Ensure",
    ):
        sym = exported[name]
        assert sym.binding == elfdeps.SymbolBinding.GLOBAL
        assert sym.type == elfdeps.SymbolType.FUNC
    # stable ABI type objects are exported as global data objects
    for name in (
        "PyList_Type",
        "PyDict_Type",
        "PyFloat_Type",
        "PyExc_ValueError",
    ):
        sym = exported[name]
        assert sym.binding == elfdeps.SymbolBinding.GLOBAL
        assert sym.type == elfdeps.SymbolType.OBJECT
