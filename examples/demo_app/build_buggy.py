#!/usr/bin/env python3
"""build_buggy.py —— 故意不可复现的构建脚本（演示用）。

埋入的非确定源（reproverify 应全部识别出来）：
  1. 绝对路径：BUILD_METADATA.json 写入构建目录的绝对路径
  2. 时间戳  ：写入当前墙钟时间（ISO / epoch 两种格式），归档 mtime 取当前时间，
               gzip 头使用默认 mtime
  3. 随机数  ：uuid4 生成 build_id，os.urandom 生成 nonce 二进制，
               打包顺序经过 random.shuffle
  4. locale  ：setlocale(LC_ALL, "") 跟随环境，数字/货币/时间格式随 locale/时区变化
另外 tar 成员保留当前用户 uid/gid，属主类问题也会暴露。
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import locale
import os
import random
import shutil
import tarfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
VERSION = "1.4.2"
WHEEL_NAME = f"demo_app-{VERSION}-py3-none-any.whl"


def _collect_source_files() -> list[Path]:
    files: list[Path] = []
    for base in (ROOT / "demo_app",):
        for p in sorted(base.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                files.append(p)
    for extra in ("README.md", "requirements.lock"):
        files.append(ROOT / extra)
    return files


def _build_metadata() -> dict:
    # 非确定源 4：跟随进程环境的 locale
    locale.setlocale(locale.LC_ALL, "")
    now = datetime.now(timezone.utc).astimezone()  # 本地时区，非确定
    # C/POSIX locale 不支持货币格式化，做兜底；不同 locale 下输出仍各不相同
    try:
        money = locale.currency(1234567.89, grouping=True)
    except ValueError:
        money = f"CURRENCY {locale.format_string('%.2f', 1234567.89, grouping=True)}"
    number = locale.format_string("%.4f", 3.14159, grouping=True)
    formatted_now = now.strftime("%a %d %b %Y %H:%M:%S %z")

    return {
        # 非确定源 1：构建机绝对路径
        "build_root": str(ROOT),
        "source_path": f"file://{ROOT}/demo_app/core.py",
        # 非确定源 2：墙钟时间，多种格式方便展示规则覆盖面
        "built_at_iso": now.isoformat(),
        "built_at_rfc": formatted_now,
        "built_at_epoch": int(time.time()),
        "built_at_epoch_ms": int(time.time() * 1000),
        # 非确定源 3：随机唯一 ID
        "build_id": str(uuid.uuid4()),
        "request_id": uuid.uuid4().hex,
        # 非确定源 4：locale 相关格式
        "locale_tag": locale.setlocale(locale.LC_ALL, ""),
        "money": money,
        "number": number,
        "tz_name": time.tzname,
    }


def _wheel_payload(metadata: dict) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for src in _collect_source_files():
        rel = src.relative_to(ROOT)
        payload[str(rel).replace(os.sep, "/")] = src.read_bytes()

    dist_info = f"demo_app-{VERSION}.dist-info"
    payload[f"{dist_info}/METADATA"] = (
        "Metadata-Version: 2.1\n"
        f"Name: demo-app\n"
        f"Version: {VERSION}\n"
        "Summary: reproducible-build demo client\n"
    ).encode()
    payload[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: demo-buggy-build\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode()
    # 非确定源 3：随机字节直接进产物
    payload[f"{dist_info}/nonce.bin"] = os.urandom(32)
    payload[f"{dist_info}/BUILD_METADATA.json"] = json.dumps(
        metadata, indent=2, ensure_ascii=False
    ).encode()

    # RECORD：内容哈希；因 nonce/metadata 每次不同，RECORD 每次也不同
    lines = []
    for name in sorted(payload):
        digest = hashlib.sha256(payload[name]).digest()
        import base64

        b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        lines.append(f"{name},sha256={b64},{len(payload[name])}")
    lines.append(f"{dist_info}/RECORD,,")
    payload[f"{dist_info}/RECORD"] = ("\n".join(lines) + "\n").encode()
    return payload


def _randomized_order(names: list[str]) -> list[str]:
    # 非确定源 3：随机打乱归档成员顺序
    order = list(names)
    random.seed()  # 不传参 → 使用系统熵
    random.shuffle(order)
    return order


def write_wheel(payload: dict[str, bytes]) -> None:
    with zipfile.ZipFile(DIST / WHEEL_NAME, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in _randomized_order(list(payload)):
            # ZipInfo 不指定 date_time → 默认当前时间（非确定源 2）
            zf.writestr(name, payload[name])


def write_zip(payload: dict[str, bytes]) -> None:
    with zipfile.ZipFile(DIST / "demo_app-portable.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name in _randomized_order(list(payload)):
            zf.writestr(f"demo_app/{name}", payload[name])


def write_targz(payload: dict[str, bytes]) -> None:
    path = DIST / "demo_app.tar.gz"
    # gzip 不传 mtime → 写入压缩时刻（非确定源 2）
    with gzip.open(path, "wb") as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for name in _randomized_order(list(payload)):
                data = payload[name]
                info = tarfile.TarInfo(name=f"demo_app/{name}")
                info.size = len(data)
                info.mtime = int(time.time())  # 非确定源 2：成员 mtime
                # 非确定源（属主）：直接采用构建机/环境给定身份，
                # 不同机器上 uid/gid/用户名不同 → 复现验证工具应识别
                info.uid = int(os.environ.get("TAR_UID", os.getuid() if hasattr(os, "getuid") else 0))
                info.gid = int(os.environ.get("TAR_GID", os.getgid() if hasattr(os, "getgid") else 0))
                info.uname = os.environ.get("TAR_UNAME", os.environ.get("USER", ""))
                info.gname = os.environ.get("TAR_GNAME", "")
                tf.addfile(info, io.BytesIO(data))


def main() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    metadata = _build_metadata()
    payload = _wheel_payload(metadata)
    write_wheel(payload)
    write_zip(payload)
    write_targz(payload)
    print(f"[buggy] 产物已写入 {DIST}")
    for p in sorted(DIST.iterdir()):
        print(f"  - {p.name} ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
