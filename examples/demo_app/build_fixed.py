#!/usr/bin/env python3
"""build_fixed.py —— 可复现的对照构建脚本。

对 build_buggy.py 中每类非确定源的消除方式：
  1. 绝对路径 → 只写项目相对路径
  2. 时间戳  → 全部从 SOURCE_DATE_EPOCH 派生；zip 固定 ZipInfo 日期，
               tar 成员 mtime 固定，gzip mtime 固定
  3. 随机数  → build_id/nonce 由源码内容哈希确定性派生；成员按名排序
  4. locale  → 显式 setlocale(LC_ALL, "C")、TZ=UTC，格式化与 locale 解耦
属主/权限 → tar filter 统一 uid/gid=0、固定 mode。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import locale
import os
import shutil
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
VERSION = "1.4.2"
WHEEL_NAME = f"demo_app-{VERSION}-py3-none-any.whl"

# 固定 epoch：优先 SOURCE_DATE_EPOCH，缺省给一个确定值
EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1700000000"))
FIXED_DT = datetime.fromtimestamp(EPOCH, tz=timezone.utc)
ZIP_DATE = FIXED_DT.timetuple()[:6]  # ZipInfo 需要 (y,m,d,H,M,S)


def _collect_source_files() -> list[Path]:
    files: list[Path] = []
    for p in sorted((ROOT / "demo_app").rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            files.append(p)
    for extra in ("README.md", "requirements.lock"):
        files.append(ROOT / extra)
    return sorted(files, key=lambda p: str(p.relative_to(ROOT)))


def _source_fingerprint() -> bytes:
    """源码内容指纹：所有输入文件（相对路径 + 内容）参与哈希。"""
    h = hashlib.sha256()
    for src in _collect_source_files():
        rel = str(src.relative_to(ROOT)).replace(os.sep, "/")
        h.update(rel.encode())
        h.update(b"\0")
        h.update(src.read_bytes())
        h.update(b"\0")
    h.update(VERSION.encode())
    return h.digest()


def _build_metadata(fingerprint: bytes) -> dict:
    # 修复 4：强制 C locale，不继承环境
    locale.setlocale(locale.LC_ALL, "C")
    # 修复 2：时间全部来自固定 epoch，时区固定 UTC
    fixed_now = FIXED_DT
    # C/POSIX locale 不支持货币格式化，做确定性兜底
    try:
        money = locale.currency(1234567.89, grouping=True)
    except ValueError:
        money = f"CURRENCY {locale.format_string('%.2f', 1234567.89, grouping=False)}"
    number = locale.format_string("%.4f", 3.14159, grouping=False)

    return {
        # 修复 1：只记录相对路径，不出现构建目录
        "build_root": ".",
        "source_path": "demo_app/core.py",
        # 修复 2：固定时间的多种表示
        "built_at_iso": fixed_now.isoformat(),
        "built_at_rfc": fixed_now.strftime("%a %d %b %Y %H:%M:%S +0000"),
        "built_at_epoch": EPOCH,
        "built_at_epoch_ms": EPOCH * 1000,
        # 修复 3：ID 由内容哈希派生，同输入同输出
        "build_id": _uuid_from_bytes(fingerprint),
        "request_id": fingerprint.hex(),
        # 修复 4：固定 locale 标签与格式
        "locale_tag": "C",
        "money": money,
        "number": number,
        "tz_name": "UTC",
    }


def _uuid_from_bytes(seed: bytes) -> str:
    """把 32 字节种子确定性地格式化成 UUID 形状（v4 字段位照填，但值由哈希决定）。"""
    h = hashlib.sha256(seed).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def _wheel_payload(metadata: dict) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for src in _collect_source_files():
        rel = src.relative_to(ROOT)
        payload[str(rel).replace(os.sep, "/")] = src.read_bytes()

    dist_info = f"demo_app-{VERSION}.dist-info"
    payload[f"{dist_info}/METADATA"] = (
        "Metadata-Version: 2.1\n"
        "Name: demo-app\n"
        f"Version: {VERSION}\n"
        "Summary: reproducible-build demo client\n"
    ).encode()
    payload[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: demo-fixed-build\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode()
    # 修复 3：nonce 由内容哈希派生，不再是 os.urandom
    payload[f"{dist_info}/nonce.bin"] = hashlib.sha256(
        b"nonce:" + _source_fingerprint()
    ).digest()
    payload[f"{dist_info}/BUILD_METADATA.json"] = json.dumps(
        metadata, indent=2, ensure_ascii=False, sort_keys=True
    ).encode()

    lines = []
    for name in sorted(payload):
        digest = hashlib.sha256(payload[name]).digest()
        b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        lines.append(f"{name},sha256={b64},{len(payload[name])}")
    lines.append(f"{dist_info}/RECORD,,")
    payload[f"{dist_info}/RECORD"] = ("\n".join(lines) + "\n").encode()
    return payload


def write_wheel(payload: dict[str, bytes]) -> None:
    with zipfile.ZipFile(DIST / WHEEL_NAME, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(payload):  # 修复 3：固定顺序
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)  # 修复 2：固定时间
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            zf.writestr(info, payload[name])


def write_zip(payload: dict[str, bytes]) -> None:
    with zipfile.ZipFile(DIST / "demo_app-portable.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(payload):
            info = zipfile.ZipInfo(f"demo_app/{name}", date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            zf.writestr(info, payload[name])


def write_targz(payload: dict[str, bytes]) -> None:
    path = DIST / "demo_app.tar.gz"
    # 修复 2：gzip mtime 固定为 epoch
    with gzip.GzipFile(path, "wb", mtime=EPOCH) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for name in sorted(payload):  # 修复 3：固定顺序
                data = payload[name]
                info = tarfile.TarInfo(name=f"demo_app/{name}")
                info.size = len(data)
                info.mtime = EPOCH  # 修复 2
                # 修复属主/权限：统一中性值
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o755 if name.endswith("/") else 0o644
                tf.addfile(info, io.BytesIO(data))


def main() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    fingerprint = _source_fingerprint()
    metadata = _build_metadata(fingerprint)
    payload = _wheel_payload(metadata)
    write_wheel(payload)
    write_zip(payload)
    write_targz(payload)
    print(f"[fixed] 产物已写入 {DIST}")
    for p in sorted(DIST.iterdir()):
        print(f"  - {p.name} ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
