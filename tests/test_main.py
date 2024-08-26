import pathlib
import subprocess
import sys
import tarfile
import zipfile


def test_main_binary() -> None:
    python = pathlib.Path(sys.executable).resolve()
    out = subprocess.check_output(["elfdeps", python], text=True)
    assert str(python) in out


def test_main_tarfile(tmp_path: pathlib.Path):
    tname = tmp_path / "test.tar.gz"
    python = pathlib.Path(sys.executable).resolve()
    with tarfile.TarFile.open(tname, mode="w:gz") as tf:
        # FIXME: remove '.so' suffix
        tf.add(python, "python-binary.so")
        tf.add(__file__, "test.py")
    out = subprocess.check_output(["elfdeps", str(tname)], text=True)
    assert "python-binary" in out


def test_main_zipfile(tmp_path: pathlib.Path) -> None:
    zname = tmp_path / "test.zip"
    python = pathlib.Path(sys.executable).resolve()
    with zipfile.ZipFile(zname, mode="w") as zf:
        # FIXME: remove '.so' suffix
        zf.write(python, "python-binary.so")
        zf.write(__file__, "test.py")
    out = subprocess.check_output(["elfdeps", str(zname)], text=True)
    assert "python-binary" in out
