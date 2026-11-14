"""全工具共享的数据模型。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    """整体可信度结论。"""

    REPRODUCIBLE = "reproducible"
    DETERMINISTIC_WITH_FIXES = "deterministic-with-fixes"
    NON_REPRODUCIBLE = "non-reproducible"
    ERROR = "error"


# 非确定性类别（同时作为扣分权重的键，见 report.py）
CATEGORY_ORDER = "entry-order"          # 归档成员顺序
CATEGORY_MTIME = "timestamp"            # 时间戳（文件 mtime / gzip mtime / 文本时间）
CATEGORY_OWNER = "owner"                # uid/gid/属主
CATEGORY_MODE = "mode"                  # 权限位
CATEGORY_ABS_PATH = "absolute-path"     # 绝对路径泄漏
CATEGORY_RANDOM = "randomness"          # 随机数 / 唯一 ID
CATEGORY_LOCALE = "locale"              # locale / 时区 / 编码
CATEGORY_MISSING = "missing-entry"      # 条目缺失或新增
CATEGORY_CODE = "code-diff"             # 真正的代码差异
CATEGORY_UNKNOWN = "unknown"            # 无法归因，需人工确认

CATEGORY_TITLES = {
    CATEGORY_ORDER: "归档成员顺序不稳定",
    CATEGORY_MTIME: "时间戳非确定",
    CATEGORY_OWNER: "属主/组信息非确定",
    CATEGORY_MODE: "权限位非确定",
    CATEGORY_ABS_PATH: "绝对路径泄漏",
    CATEGORY_RANDOM: "随机数/唯一ID非确定",
    CATEGORY_LOCALE: "locale/时区相关非确定",
    CATEGORY_MISSING: "条目集合不一致",
    CATEGORY_CODE: "真实代码差异",
    CATEGORY_UNKNOWN: "无法自动归因",
}


@dataclass
class Evidence:
    """一条差异的两边证据。"""

    a: str
    b: str
    note: str = ""


@dataclass
class Finding:
    """单条归因结论。"""

    rule_id: str
    category: str
    title: str
    location: str
    remediation: str
    confidence: str = "high"          # high / medium / low
    scope: str = "entry"              # raw / archive / entry
    count: int = 1
    evidence: Evidence | None = None
    diff: str = ""                    # 仅 code-diff 使用（unified diff）


@dataclass
class ArtifactReport:
    """单个产物的比对结果。"""

    name: str
    kind: str
    size_a: int
    size_b: int
    digest_a: str
    digest_b: str
    entries_total: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def raw_equal(self) -> bool:
        return self.digest_a == self.digest_b

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts


@dataclass
class BuildInfo:
    """一次构建的环境与产物信息。"""

    root: str
    ok: bool
    returncode: int
    started_at: float
    finished_at: float
    env: dict[str, str]
    artifacts: list[str] = field(default_factory=list)
    log: str = ""
    error: str = ""


@dataclass
class RunReport:
    """一次完整复现验证的总报告。"""

    source: str
    build_cmd: str
    workdir: str
    vary_env: bool
    source_date_epoch: int
    build_a: BuildInfo
    build_b: BuildInfo
    artifacts: list[ArtifactReport] = field(default_factory=list)
    unpaired: list[tuple[str, str]] = field(default_factory=list)
    verdict: Verdict = Verdict.ERROR
    score: int = 100
    score_notes: list[str] = field(default_factory=list)
    generated_at: str = ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
