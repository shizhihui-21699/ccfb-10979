"""归档解析层的单元测试。"""

import gzip
import io
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from reproverify.archives import classify_artifact, open_archive


class ClassifyTests(unittest.TestCase):
    def test_suffixes(self):
        self.assertEqual(classify_artifact("x-1.0-py3-none-any.whl"), "zip")
        self.assertEqual(classify_artifact("x.zip"), "zip")
        self.assertEqual(classify_artifact("x.tar.gz"), "tar")
        self.assertEqual(classify_artifact("x.tgz"), "tar")
        self.assertEqual(classify_artifact("x.tar.xz"), "tar")
        self.assertEqual(classify_artifact("x.bin"), "plain")


class ArchiveViewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _zip(self, name, entries):
        p = Path(self.tmp) / name
        with zipfile.ZipFile(p, "w") as zf:
            for arc, data in entries:
                zf.writestr(arc, data)
        return p

    def _targz(self, name, entries, mtime=None):
        p = Path(self.tmp) / name
        mtime = int(time.time()) if mtime is None else mtime
        with gzip.GzipFile(p, "wb", mtime=mtime) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                for arc, data in entries:
                    info = tarfile.TarInfo(arc)
                    info.size = len(data)
                    info.mtime = mtime
                    tf.addfile(info, io.BytesIO(data))
        return p

    def test_open_zip(self):
        p = self._zip("a.whl", [("x/__init__.py", b"print(1)"), ("x/y.txt", b"hi")])
        view = open_archive(p)
        self.assertEqual(view.kind, "zip")
        self.assertEqual(len(view.entries), 2)
        self.assertEqual(view.by_name()["x/y.txt"].data, b"hi")
        self.assertEqual(view.ordered_names, ["x/__init__.py", "x/y.txt"])

    def test_open_targz_and_gzip_mtime(self):
        p = self._targz("a.tar.gz", [("a/f", b"data")], mtime=1700000000)
        view = open_archive(p)
        self.assertEqual(view.kind, "tar")
        self.assertEqual(view.gzip_mtime, 1700000000.0)
        entry = view.by_name()["a/f"]
        self.assertEqual(entry.data, b"data")
        self.assertEqual(entry.mtime, 1700000000.0)

    def test_tar_path_traversal_rejected(self):
        p = Path(self.tmp) / "evil.tar"
        with tarfile.open(p, "w") as tf:
            info = tarfile.TarInfo("../escape.txt")
            data = b"x"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        with self.assertRaises(ValueError):
            open_archive(p)

    def test_plain_file(self):
        p = Path(self.tmp) / "f.bin"
        p.write_bytes(b"\x00\x01\x02")
        view = open_archive(p)
        self.assertEqual(view.kind, "plain")
        self.assertEqual(view.entries[0].data, b"\x00\x01\x02")


if __name__ == "__main__":
    unittest.main()
