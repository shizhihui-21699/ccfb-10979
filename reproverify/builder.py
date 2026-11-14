"""受控双构建：在两个干净目录中用锁定环境各执行一次构建。

环境控制手段（两边一致，除探测模式外）：
  LC_ALL/LANG=C.UTF-8、TZ=UTC、PYTHONHASHSEED=0、不写 .pyc、
  SOURCE_DATE_EPOCH 固定；PATH 等少量必要变量从宿主透传。
两边唯一天然的不同是工作目录绝对路径——这正是检测路径泄漏所必需的。
"""

from __future__ import annotations

import locale
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .model import BuildInfo
from .rules import BuildContext

# 允许从宿主透传的变量白名单（其余全部清空）
_PASSTHROUGH_VARS = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SYSTEMROOT", "COMSPEC")

# vary-env 探测时 B 侧使用的 locale / 时区
PROBE_LOCALE = "en_US.UTF-8"
PROBE_TZ = "America/New_York"


def locale_available(name: str) -> bool:
    for enc in (name, name.replace(".UTF-8", "")):
        try:
            with _suppress_stderr():
                locale.setlocale(locale.LC_ALL, enc)
            locale.setlocale(locale.LC_ALL, "C")
            return True
        except locale.Error:
            continue
    return False


class _suppress_stderr:
    def __enter__(self):
        self.fd = os.dup(2)
        self.null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(self.null, 2)

    def __exit__(self, *exc):
        os.dup2(self.fd, 2)
        os.close(self.null)
        os.close(self.fd)


@dataclass
class BuildConfig:
    source: Path
    workdir: Path
    build_cmd: str
    dist_subdir: str
    epoch: int
    vary_env: bool
    timeout: int
    keep: bool


def base_env(epoch: int) -> dict[str, str]:
    env = {v: os.environ.get(v, "") for v in _PASSTHROUGH_VARS if os.environ.get(v)}
    env.update(
        {
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "LC_NUMERIC": "C",
            "TZ": "UTC",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TERM": "dumb",
        }
    )
    return env


def _probe_env(base: dict[str, str]) -> dict[str, str]:
    """B 侧探测环境：换 locale / 时区 / 归档身份，验证产物是否随它们变化。"""
    env = dict(base)
    if locale_available(PROBE_LOCALE):
        env["LC_ALL"] = PROBE_LOCALE
        env["LANG"] = PROBE_LOCALE
        env["LC_NUMERIC"] = PROBE_LOCALE
    else:
        # 退化：C.UTF-8 与 C 的差异很弱，但仍保持结构
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["LC_NUMERIC"] = "C"
    env["TZ"] = PROBE_TZ
    # 模拟另一台构建机的 tar 身份（uid/gid/属主名）
    env["TAR_UID"] = "1000"
    env["TAR_GID"] = "1000"
    env["TAR_UNAME"] = "ci-builder"
    env["TAR_GNAME"] = "ci-group"
    return env


def _prepare_source(src: Path, dst: Path) -> None:
    """把源码树复制到干净目录；跳过 VCS、缓存与产物目录。"""
    skip_dirs = {".git", ".hg", "__pycache__", ".pytest_cache", "dist", "build", ".venv", "venv"}

    def ignore(dirpath: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        if Path(dirpath) == src:
            ignored |= {n for n in names if n in skip_dirs}
        else:
            ignored |= {n for n in names if n in skip_dirs}
        return ignored

    shutil.copytree(src, dst, ignore=ignore, symlinks=False)


def _run_build(root: Path, cfg: BuildConfig, env: dict[str, str]) -> BuildInfo:
    started = time.time()
    try:
        proc = subprocess.run(
            cfg.build_cmd,
            cwd=root,
            env=env,
            shell=True,
            capture_output=True,
            text=True,
            timeout=cfg.timeout,
        )
        finished = time.time()
        log = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
        artifacts = _collect_artifacts(root / cfg.dist_subdir)
        return BuildInfo(
            root=str(root),
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            started_at=started,
            finished_at=finished,
            env=dict(env),
            artifacts=artifacts,
            log=log[-8000:],
        )
    except subprocess.TimeoutExpired as e:
        return BuildInfo(
            root=str(root),
            ok=False,
            returncode=-1,
            started_at=started,
            finished_at=time.time(),
            env=dict(env),
            error=f"构建超时（{cfg.timeout}s）: {e}",
        )
    except OSError as e:
        return BuildInfo(
            root=str(root),
            ok=False,
            returncode=-1,
            started_at=started,
            finished_at=time.time(),
            env=dict(env),
            error=f"无法启动构建: {e}",
        )


def _collect_artifacts(dist: Path) -> list[str]:
    if not dist.is_dir():
        return []
    out: list[str] = []
    for p in sorted(dist.rglob("*")):
        if p.is_file():
            out.append(str(p.relative_to(dist)))
    return out


def run_double_build(cfg: BuildConfig) -> tuple[BuildInfo, BuildInfo, BuildContext]:
    """执行 A/B 双构建，返回两边信息与归因上下文。"""
    dir_a = cfg.workdir / "build-a" / "src"
    dir_b = cfg.workdir / "build-b" / "src"
    for d in (dir_a, dir_b):
        if d.exists():
            shutil.rmtree(d)
        d.parent.mkdir(parents=True, exist_ok=True)

    _prepare_source(cfg.source, dir_a)
    _prepare_source(cfg.source, dir_b)

    env_a = base_env(cfg.epoch)
    env_b = _probe_env(env_a) if cfg.vary_env else dict(env_a)

    info_a = _run_build(dir_a, cfg, env_a)
    info_b = _run_build(dir_b, cfg, env_b)

    ctx = BuildContext(
        root_a=str(dir_a),
        root_b=str(dir_b),
        build_started=min(info_a.started_at, info_b.started_at),
        build_finished=max(info_a.finished_at, info_b.finished_at),
        epoch=cfg.epoch,
    )
    return info_a, info_b, ctx
