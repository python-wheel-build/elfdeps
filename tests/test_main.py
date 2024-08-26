import pathlib
import shutil
import subprocess
import sys
import tarfile
import zipfile


def test_main_binary(tmp_path: pathlib.Path) -> None:
    python = tmp_path / "python"
    shutil.copy2(sys.executable, python)
    out = subprocess.check_output(["elfdeps", python], text=True)
    assert str(python) in out
    out = subprocess.check_output(["elfdeps", str(tmp_path)], text=True)
    assert str(python) in out


def test_main_tarfile(tmp_path: pathlib.Path) -> None:
    tname = tmp_path / "test.tar.gz"
    python = pathlib.Path(sys.executable).resolve()
    with tarfile.TarFile.open(tname, mode="w:gz") as tf:
        # FIXME: remove '.so' suffix
        tf.add(python, "python-binary")
        tf.add(__file__, "test.py")
    out = subprocess.check_output(["elfdeps", str(tname)], text=True)
    assert "python-binary" in out


def test_main_zipfile(tmp_path: pathlib.Path) -> None:
    zname = tmp_path / "test.zip"
    python = pathlib.Path(sys.executable).resolve()
    with zipfile.ZipFile(zname, mode="w") as zf:
        zf.write(python, "python-binary")
        zf.write(__file__, "test.py")
    out = subprocess.check_output(["elfdeps", str(zname)], text=True)
    assert "python-binary" in out
