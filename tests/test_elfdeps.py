import pathlib
import sys
import tarfile
import zipfile

import pytest

import elfdeps


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
    for libdir in [pathlib.Path("/lib"), pathlib.Path("/lib64")]:
        libc = libdir / "libc.so.6"
        if libc.is_file():
            found = True
            info = elfdeps.analyze_file(libc)
            assert info.provides

    if not found:
        pytest.skip("libc not found")
