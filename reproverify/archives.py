"""归档解包层：把 tar / zip / wheel 统一成可按成员名访问的 ArchiveView。

不解压到临时目录，全部在内存中读取，避免在不受信任的目录里落盘；
tar 成员做路径穿越检查，防止恶意 tar（带 `../` 或绝对路径）逃逸。
"""

from __future__ import annotations

import gzip
import os
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass
class Entry:
    """归档内的一个成员（或普通文件本身）。"""

    name: str
    data: bytes
    mtime: float | None
    size: int
    mode: int | None
    uid: int | None
    gid: int | None
    uname: str | None
    gname: str | None
    is_dir: bool = False
    crc32: int | None = None          # zip 专属，用于内容快速旁证


@dataclass
class ArchiveView:
    kind: str                         # zip / tar / plain
    path: str
    entries: list[Entry]
    gzip_mtime: float | None = None   # .tar.gz 外层 gzip 头的 mtime
    gzip_owner_os: str | None = None
    ordered_names: list[str] | None = None  # 归档里成员的物理顺序

    def by_name(self) -> dict[str, Entry]:
        return {e.name: e for e in self.entries}


def classify_artifact(name: str) -> str:
    n = name.lower()
    if n.endswith((".whl", ".egg", ".zip")):
        return "zip"
    if n.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
        return "tar"
    return "plain"


def _safe_member_name(raw: str) -> str:
    """tar 成员名安全检查：拒绝绝对路径与 `..` 穿越。"""
    p = PurePosixPath(raw)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        raise ValueError(f"tar 成员路径不安全: {raw!r}")
    return raw


def _peek_gzip_mtime(path: Path) -> float | None:
    """读取 gzip 头部 mtime（tar.gz 的外层时间戳，常见非确定源）。"""
    try:
        with path.open("rb") as fh:
            magic = fh.read(2)
            if magic != b"\x1f\x8b":
                return None
            import struct

            fh.read(2)  # 压缩方法(1) + 标志位(1)
            # 紧接着就是 4 字节 little-endian mtime
            mtime = struct.unpack("<I", fh.read(4))[0]
            return float(mtime)
    except OSError:
        return None


def open_archive(path: Path) -> ArchiveView:
    kind = classify_artifact(path.name)
    if kind == "zip":
        return _open_zip(path)
    if kind == "tar":
        return _open_tar(path)
    return _open_plain(path)


def _open_zip(path: Path) -> ArchiveView:
    entries: list[Entry] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            # 统一成正斜杠，去掉目录条目末尾的分隔符做归一比较
            name = info.filename.replace("\\", "/")
            is_dir = info.is_dir()
            data = b"" if is_dir else zf.read(info)
            mode = (info.external_attr >> 16) & 0xFFFF
            entries.append(
                Entry(
                    name=name.rstrip("/"),
                    data=data,
                    mtime=float(_zip_dos_time_to_epoch(info)),
                    size=info.file_size,
                    mode=mode or None,
                    uid=None,
                    gid=None,
                    uname=None,
                    gname=None,
                    is_dir=is_dir,
                    crc32=info.CRC,
                )
            )
        ordered = [i.filename.replace("\\", "/").rstrip("/") for i in zf.infolist()]
    return ArchiveView(kind="zip", path=str(path), entries=entries, ordered_names=ordered)


def _zip_dos_time_to_epoch(info: zipfile.ZipInfo) -> int:
    import datetime

    try:
        dt = datetime.datetime(
            *info.date_time, tzinfo=datetime.timezone.utc
        )
        return int(dt.timestamp())
    except (ValueError, OverflowError):
        return 0


def _open_tar(path: Path) -> ArchiveView:
    gzip_mtime = None
    if path.name.lower().endswith((".tar.gz", ".tgz")):
        gzip_mtime = _peek_gzip_mtime(path)

    entries: list[Entry] = []
    ordered: list[str] = []
    # mode r:* 自动识别 gz/bz2/xz
    with tarfile.open(path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = _safe_member_name(member.name).rstrip("/")
            ordered.append(name)
            if member.isdir():
                data = b""
            else:
                extracted = tf.extractfile(member)
                data = extracted.read() if extracted is not None else b""
            entries.append(
                Entry(
                    name=name,
                    data=data,
                    mtime=float(member.mtime),
                    size=member.size,
                    mode=member.mode,
                    uid=member.uid,
                    gid=member.gid,
                    uname=member.uname,
                    gname=member.gname,
                    is_dir=member.isdir(),
                )
            )
    return ArchiveView(
        kind="tar",
        path=str(path),
        entries=entries,
        gzip_mtime=gzip_mtime,
        ordered_names=ordered,
    )


def _open_plain(path: Path) -> ArchiveView:
    data = path.read_bytes()
    st = path.stat()
    entry = Entry(
        name=path.name,
        data=data,
        mtime=st.st_mtime,
        size=len(data),
        mode=st.st_mode & 0o7777,
        uid=st.st_uid,
        gid=st.st_gid,
        uname=None,
        gname=None,
    )
    return ArchiveView(
        kind="plain",
        path=str(path),
        entries=[entry],
        ordered_names=[path.name],
    )
