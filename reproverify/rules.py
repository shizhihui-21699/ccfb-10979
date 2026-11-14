"""差异归因规则。

设计思路：每条规则是一个“归一化器”——把它认识的非确定 token 替换成占位符。
按固定顺序串成规则链（绝对路径 → 时间戳 → locale → 随机数），两边文本经过
同一条链后若变成一致，则差异全部可归因；仍不一致的部分判定为真实代码差异。

规则只做形态识别 + 时间窗口校验，不靠文件名猜测，避免把正常代码误判成噪声。
"""

from __future__ import annotations

import datetime as _dt
import math
import re
import unicodedata
from dataclasses import dataclass, field

from .model import (
    CATEGORY_ABS_PATH,
    CATEGORY_CODE,
    CATEGORY_LOCALE,
    CATEGORY_MTIME,
    CATEGORY_RANDOM,
)

# ---------------------------------------------------------------------------
# 消除建议（所有 remediation 文案集中在这，方便统一维护）
# ---------------------------------------------------------------------------

REMEDIATIONS = {
    CATEGORY_ABS_PATH: (
        "构建过程把工作目录写进了产物。消除办法：只记录项目相对路径；"
        "设置 BUILD_DIR=/build 等固定中性路径；打包前对路径做 relativize；"
        "调试信息用 -ffile-prefix-map=/源码目录=. 重映射。"
    ),
    CATEGORY_MTIME: (
        "产物里写入了构建时刻。消除办法：遵循 SOURCE_DATE_EPOCH 规范，"
        "所有时间戳从该环境变量派生；zip 用 ZipInfo 固定日期时间，"
        "tar 用 filter 统一 mtime，gzip 传固定 mtime；源码本身不要生成时间戳。"
    ),
    CATEGORY_LOCALE: (
        "输出随 locale/时区变化。消除办法：构建环境固定 LC_ALL=C、LANG=C、"
        "TZ=UTC；代码中显式使用 locale 无关的格式化（如 strftime 固定格式、"
        "数字格式化强制 en_US/C），不要依赖进程默认 locale。"
    ),
    CATEGORY_RANDOM: (
        "产物包含随机/每次唯一的值。消除办法：不要在构建期调用 uuid4/random/"
        "tempfile 生成名字或内容；需要唯一标识时用源码内容哈希（如 git commit "
        "或文件 sha256）派生；临时目录使用固定名称。"
    ),
    CATEGORY_CODE: (
        "排除全部已知非确定形态后内容仍不一致——这是真实的源码/构建逻辑差异，"
        "需要人工确认两次构建的源码与依赖锁定是否真的相同。"
    ),
    "entry-order": (
        "归档成员写入顺序不稳定。消除办法：打包前按成员名排序（sorted(namelist)），"
        "不要遍历 dict/set/glob 的原始顺序；glob 结果显式 sort。"
    ),
    "owner": (
        "tar 记录了构建机的 uid/gid/属主名。消除办法：tarfile 写入时用 filter "
        "统一 uid=gid=0、uname=gname=''（或固定值）。"
    ),
    "mode": (
        "权限位在两台机器上不一致（umask/文件系统差异）。消除办法：tar filter "
        "中按文件类型固定 mode（目录 0o755、普通文件 0o644）。"
    ),
    "gzip-mtime": (
        "gzip 头里写入了压缩时刻（即使 tar 内容一致字节也不同）。消除办法："
        "gzip.GzipFile(..., mtime=SOURCE_DATE_EPOCH) 或压缩后清零 gzip mtime。"
    ),
    "missing-entry": (
        "两次构建的成员集合不同。消除办法：检查构建脚本是否按 glob/dict 顺序"
        "条件性生成文件、是否有随机文件名；把输入文件清单显式化并排序。"
    ),
}

TITLES = {
    CATEGORY_ABS_PATH: "内容中发现构建目录绝对路径",
    CATEGORY_MTIME: "内容中发现构建时间戳",
    CATEGORY_LOCALE: "内容中发现 locale/时区相关格式差异",
    CATEGORY_RANDOM: "内容中发现随机生成的唯一标识/数据",
    CATEGORY_CODE: "无法归因的真实内容差异",
    "entry-order": "归档成员顺序不一致",
    "owner": "归档成员属主信息不一致",
    "mode": "归档成员权限位不一致",
    "gzip-mtime": "gzip 头部 mtime 不一致",
    "missing-entry": "归档成员集合不一致",
}


@dataclass
class BuildContext:
    """两次构建的已知事实，供规则做时间窗口/路径识别。"""

    root_a: str
    root_b: str
    build_started: float          # 两次构建中最早的开始时间
    build_finished: float         # 两次构建中最晚的结束时间
    epoch: int                    # 注入的 SOURCE_DATE_EPOCH

    @property
    def time_window(self) -> tuple[int, int]:
        # 放宽 7 天：容纳跨时区显示、格式化精度、连续构建间隔以及子进程
        # 启动/收尾的时钟边界；真实源码里的历史时间戳（如 SOURCE_DATE_EPOCH
        # 指向的 2023 年）仍落在窗口外，不会被误判
        return int(self.build_started) - 7 * 86400, int(self.build_finished) + 7 * 86400


@dataclass
class RuleResult:
    rule_id: str
    category: str
    confidence: str
    samples: list[str] = field(default_factory=list)
    hit_count: int = 0


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(s: str) -> int:
    classes = 0
    if re.search(r"[a-z]", s):
        classes += 1
    if re.search(r"[A-Z]", s):
        classes += 1
    if re.search(r"[0-9]", s):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", s):
        classes += 1
    return classes


# ---------------------------------------------------------------------------
# 规则 1：绝对路径
# ---------------------------------------------------------------------------

class AbsPathRule:
    rule_id = "abs-path"
    category = CATEGORY_ABS_PATH

    # 通用 POSIX 路径：必须出现在词首/引号/空白/等号之后，避免把 "money" 这类单词
    # 或前序规则留下的 $占位符误判成路径
    _GENERIC_POSIX = re.compile(
        r"(?P<pre>^|[\s=:'\"(])(?P<q>['\"]?)/(?:[A-Za-z0-9._\-]+/){1,}[A-Za-z0-9._\-]+"
    )
    _WINDOWS = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+")
    _FILE_URI = re.compile(r"file://[^\s'\"）)]+")

    def __init__(self, ctx: BuildContext):
        roots = sorted({ctx.root_a, ctx.root_b}, key=len, reverse=True)
        self._root_res = [re.compile(re.escape(r)) for r in roots]
        self._root_hit = False

    def normalize(self, text: str) -> tuple[str, list[str]]:
        samples: list[str] = []
        # 优先替换真实构建根（高置信）
        for rx in self._root_res:
            text, n = rx.subn("$BUILDROOT", text)
            if n:
                self._root_hit = True
        text, n = self._FILE_URI.subn("file://$PATH", text)
        if n:
            samples.append("file:// URI")
        text, n = self._WINDOWS.subn("$WINPATH", text)
        if n:
            samples.append("Windows 绝对路径")

        def _posix_repl(m: re.Match) -> str:
            q = m.group("q")
            samples.append(m.group(0).strip("'\"")[:120])
            return f"{m.group('pre')}{q}$PATH"

        text = self._GENERIC_POSIX.sub(_posix_repl, text)
        return text, samples[:5]

    @property
    def confidence(self) -> str:
        return "high" if self._root_hit else "medium"


# ---------------------------------------------------------------------------
# 规则 2：时间戳
# ---------------------------------------------------------------------------

class TimestampRule:
    rule_id = "timestamp"
    category = CATEGORY_MTIME

    _PATTERNS: list[tuple[str, re.Pattern[str], str]] = []

    def _init_patterns(self) -> None:
        if self._PATTERNS:
            return
        # (名称, 正则, strptime 格式或 epoch/epoch-ms)
        self._PATTERNS = [
            (
                "ISO-8601",
                re.compile(
                    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
                    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
                ),
                "iso",
            ),
            (
                "斜杠日期",
                re.compile(r"\d{4}/\d{1,2}/\d{1,2}[ T]\d{2}:\d{2}:\d{2}"),
                "slash",
            ),
            (
                "点分日期",
                re.compile(r"\d{4}\.\d{1,2}\.\d{1,2}[ T]\d{2}:\d{2}:\d{2}"),
                "dot",
            ),
            (
                "RFC2822",
                re.compile(r"\w{3},?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?"),
                "rfc",
            ),
            ("epoch秒", re.compile(r"(?<![\d.])\d{10}(?![\d.])"), "epoch"),
            ("epoch毫秒", re.compile(r"(?<![\d.])\d{13}(?![\d.])"), "epoch-ms"),
        ]

    def __init__(self, ctx: BuildContext):
        self.ctx = ctx
        self._init_patterns()

    def _in_window(self, ts: float) -> bool:
        lo, hi = self.ctx.time_window
        return lo <= ts <= hi

    def _parse_structured(self, kind: str, raw: str) -> float | None:
        s = raw.replace(",", ".") if "," in raw and kind == "iso" else raw
        try:
            if kind == "iso":
                s = s.replace("Z", "+00:00")
                # 兼容 "2026-11-15 05:30:00.123456" 与带时区形式
                dt = _dt.datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=_dt.timezone.utc)
                return dt.timestamp()
            if kind == "slash":
                dt = _dt.datetime.strptime(s.split(" ")[0].split("T")[0], "%Y/%m/%d")
                return dt.replace(tzinfo=_dt.timezone.utc).timestamp()
            if kind == "dot":
                dt = _dt.datetime.strptime(s.split(" ")[0].split("T")[0], "%Y.%m.%d")
                return dt.replace(tzinfo=_dt.timezone.utc).timestamp()
            if kind == "rfc":
                return _dt.datetime.strptime(s, "%a %d %b %Y %H:%M:%S %z").timestamp()
        except (ValueError, OverflowError):
            return None
        return None

    def normalize(self, text: str) -> tuple[str, list[str]]:
        samples: list[str] = []

        def make_repl(kind: str):
            def repl(m: re.Match) -> str:
                raw = m.group(0)
                ok = False
                if kind == "epoch":
                    ok = self._in_window(int(raw))
                elif kind == "epoch-ms":
                    ok = self._in_window(int(raw) / 1000)
                else:
                    ts = self._parse_structured(kind, raw)
                    ok = ts is not None and self._in_window(ts)
                if ok:
                    if len(samples) < 5:
                        samples.append(raw[:60])
                    return "$TIMESTAMP"
                return raw

            return repl

        for name, rx, kind in self._PATTERNS:
            text = rx.sub(make_repl(kind), text)
        return text, samples


# ---------------------------------------------------------------------------
# 规则 3：locale / 时区 / 编码
# ---------------------------------------------------------------------------

class LocaleRule:
    rule_id = "locale"
    category = CATEGORY_LOCALE

    _US_GROUPED = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?")
    _EU_GROUPED = re.compile(r"\d{1,3}(?:\.\d{3})+,\d+")
    _CURRENCY = re.compile(r"[€$£¥]\s?\d[\d.,\s]*\d?")
    # 无符号货币前缀（C locale 兜底输出 "CURRENCY 1234567.89" 这类形态）
    _CURRENCY_WORD = re.compile(r"\bCURRENCY\s+\d[\d.,]*")
    _BARE_EU_DECIMAL = re.compile(r"(?<![\d.])\d+,\d+(?![\d])")
    # 纯整数（无标点）：让两侧分别归一化后也能收敛到同一占位符。
    # 负向断言保证不会切碎 UUID（含连字符的十六进制串）；
    # 不限制引号上下文，使 "CURRENCY 1234567.89" 这类字符串内数字也能归一
    _PLAIN_INTEGER = re.compile(r"(?<![\d.])(?<![0-9a-fA-F-])\d{3,}(?![\d.,])(?![0-9a-fA-F-])")
    # 小数（含小数点的纯数字序列），同样做 locale 无关归一
    _PLAIN_DECIMAL = re.compile(r"(?<![\d.])(?<![0-9a-fA-F-])\d+\.\d+(?![\d])")
    # JSON/配置中的字符串“值”（冒号右侧），覆盖 locale 标签、时区名等，
    # 只匹配纯字母/点/连字符的短 token，避免碰到路径、UUID、句子
    _QUOTED_VALUE = re.compile(r'(:\s*)"([A-Za-z][A-Za-z0-9_.+\-]{1,31})"')
    # 常见时区缩写/名称（TZ 环境变量产物），用边界限制为独立词
    _TZ_ABBR = re.compile(r"\b(?:UTC|GMT|[ECMP][SD]T)\b")

    def normalize(self, text: str) -> tuple[str, list[str]]:
        samples: list[str] = []

        def repl_us(m: re.Match) -> str:
            samples.append(m.group(0))
            return "$NUMBER"

        def repl_eu(m: re.Match) -> str:
            samples.append(m.group(0))
            return "$NUMBER"

        def repl_cur(m: re.Match) -> str:
            samples.append(m.group(0))
            # 整体替换成单一占位符，吞掉原有的 $/€ 等货币符号，避免出现 $$NUMBER
            return "$AMOUNT"

        # 货币规则必须先于纯数字分组规则，否则 $1,234.56 的数字部分会被
        # 提前替换成 $NUMBER，货币符号残留导致两侧占位符不一致
        text = self._CURRENCY.sub(repl_cur, text)
        text = self._CURRENCY_WORD.sub(repl_cur, text)
        text = self._US_GROUPED.sub(repl_us, text)
        text = self._EU_GROUPED.sub(repl_eu, text)
        text = self._BARE_EU_DECIMAL.sub(repl_eu, text)
        text = self._PLAIN_INTEGER.sub(repl_us, text)
        text = self._PLAIN_DECIMAL.sub(repl_us, text)

        def repl_quoted(m: re.Match) -> str:
            samples.append(m.group(2))
            return f'{m.group(1)}"$LOCALE_LITERAL"'

        text = self._QUOTED_VALUE.sub(repl_quoted, text)

        def repl_tz(m: re.Match) -> str:
            samples.append(m.group(0))
            return "$TZ"

        text = self._TZ_ABBR.sub(repl_tz, text)
        return text, samples[:5]

    @property
    def confidence(self) -> str:
        return "medium"


# ---------------------------------------------------------------------------
# 规则 4：随机数 / 唯一 ID
# ---------------------------------------------------------------------------

class RandomRule:
    rule_id = "random"
    category = CATEGORY_RANDOM

    _UUID = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    _HEX_BLOB = re.compile(r"\b0?x?[0-9a-fA-F]{32,}\b")
    _PTR = re.compile(r"\b0x[0-9a-fA-F]{6,}\b")
    _TMP_NAME = re.compile(r"\btmp[0-9a-zA-Z_]{6,}\b")
    # base64 URL-safe 无填充摘要（wheel RECORD 的 sha256=... 典型形态）。
    # 不能用 \b：摘要可能以 - 或 _ 开头，而前面是 =/, 等非单词字符，
    # 那种情况下 \b 不成立会导致整条摘要漏匹配（曾造成偶发误报 code-diff）
    _B64_DIGEST = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}={0,2}(?![A-Za-z0-9_\-])")
    # 跳过已被前序规则替换出的 $占位符，避免把占位符再切碎
    _TOKEN = re.compile(r"(?<!\$)[A-Za-z0-9_\-]{16,}")

    def __init__(self, high_confidence_only: bool = False):
        self.high_confidence_only = high_confidence_only
        self._last_confidence = "medium"

    def normalize(self, text: str) -> tuple[str, list[str]]:
        samples: list[str] = []
        high_conf = False

        def collect(m: re.Match, marker: str, confident: bool) -> str:
            nonlocal high_conf
            if confident:
                high_conf = True
            if len(samples) < 5:
                samples.append(f"{marker}:{m.group(0)[:60]}")
            return f"${marker}"

        text = self._UUID.sub(lambda m: collect(m, "UUID", True), text)
        text = self._PTR.sub(lambda m: collect(m, "PTR", True), text)
        text = self._HEX_BLOB.sub(lambda m: collect(m, "HEX", True), text)
        text = self._B64_DIGEST.sub(lambda m: collect(m, "B64DIGEST", True), text)

        if self.high_confidence_only:
            # 第一阶段只做高置信替换，熵判定留给末阶段
            self._last_confidence = "high" if high_conf else "medium"
            return text, samples

        text = self._TMP_NAME.sub(lambda m: collect(m, "TMP", False), text)

        def token_repl(m: re.Match) -> str:
            tok = m.group(0)
            # 纯单词（标识符/英文句子片段）不算随机
            if tok.isalpha() or tok.islower() or tok.isupper():
                return tok
            if _char_classes(tok) >= 2 and _shannon_entropy(tok) > 4.0:
                if len(samples) < 5:
                    samples.append(f"ENTROPY:{tok[:60]}")
                return "$RANDOM_TOKEN"
            return tok

        text = self._TOKEN.sub(token_repl, text)
        self._last_confidence = "high" if high_conf else "medium"
        return text, samples

    @property
    def confidence(self) -> str:
        return getattr(self, "_last_confidence", "medium")


# ---------------------------------------------------------------------------
# 规则链 + 文本解释
# ---------------------------------------------------------------------------

@dataclass
class TextExplanation:
    results: list[RuleResult]
    fully_explained: bool
    unicode_normalized: bool = False


def _build_chain(ctx: BuildContext):
    # 高置信、形态明确的随机模式先跑，占位符会保护它们不被后续规则切碎；
    # 之后依次是绝对路径、时间戳、locale，最后才是低置信的熵判定 token。
    return [
        RandomRule(high_confidence_only=True),
        AbsPathRule(ctx),
        TimestampRule(ctx),
        LocaleRule(),
        RandomRule(high_confidence_only=False),
    ]


def explain_text(text_a: str, text_b: str, ctx: BuildContext) -> TextExplanation:
    """对两段不等的文本跑规则链，返回命中的规则与是否完全解释。"""
    cur_a, cur_b = text_a, text_b
    results: list[RuleResult] = []

    for rule in _build_chain(ctx):
        new_a, samples_a = rule.normalize(cur_a)
        new_b, samples_b = rule.normalize(cur_b)
        samples = (samples_a + samples_b)[:5]
        hit = (new_a != cur_a) or (new_b != cur_b)
        if hit:
            results.append(
                RuleResult(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    confidence=getattr(rule, "confidence", "medium"),
                    samples=samples,
                    hit_count=len(samples),
                )
            )
        cur_a, cur_b = new_a, new_b

    if cur_a == cur_b:
        return TextExplanation(results, True)

    # Unicode 规范化后一致 → 编码/NFC 差异，归入 locale 类
    if unicodedata.normalize("NFC", cur_a) == unicodedata.normalize("NFC", cur_b):
        results.append(
            RuleResult(
                rule_id="unicode-nfc",
                category=CATEGORY_LOCALE,
                confidence="medium",
                samples=["Unicode 规范化形式不同（NFC/NFD）"],
            )
        )
        return TextExplanation(results, True, unicode_normalized=True)

    return TextExplanation(results, False)


def make_unified_diff(text_a: str, text_b: str, name_a: str, name_b: str, limit: int = 200) -> str:
    import difflib

    diff = difflib.unified_diff(
        text_a.splitlines(),
        text_b.splitlines(),
        fromfile=name_a,
        tofile=name_b,
        lineterm="",
    )
    lines = list(diff)
    if len(lines) > limit:
        lines = lines[:limit] + [f"...（截断，共 {len(lines)} 行差异）"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 二进制差异的启发式归因
# ---------------------------------------------------------------------------

def explain_bytes(data_a: bytes, data_b: bytes, ctx: BuildContext) -> list[RuleResult]:
    """无法按文本解码时的兜底归因：从 ASCII 片段里找路径/随机 token，
    否则按差异区域的熵判定随机数据。"""
    results: list[RuleResult] = []

    # 在 ascii 可解码片段上跑轻量规则
    text_a = data_a.decode("ascii", errors="ignore")
    text_b = data_b.decode("ascii", errors="ignore")
    if text_a != text_b:
        expl = explain_text(text_a, text_b, ctx)
        results.extend(expl.results)
        if expl.fully_explained:
            return results

    # 找公共前缀/后缀，取中间差异区
    common_lo = 0
    max_lo = min(len(data_a), len(data_b))
    while common_lo < max_lo and data_a[common_lo] == data_b[common_lo]:
        common_lo += 1
    common_hi = 0
    while (
        common_hi < max_lo - common_lo
        and data_a[-1 - common_hi] == data_b[-1 - common_hi]
    ):
        common_hi += 1
    middle = data_a[common_lo: len(data_a) - common_hi if common_hi else len(data_a)]
    entropy = _shannon_entropy("".join(chr(b) for b in middle[:4096]))

    if entropy > 3.5 or len(data_a) != len(data_b):
        results.append(
            RuleResult(
                rule_id="random-bytes",
                category=CATEGORY_RANDOM,
                confidence="medium",
                samples=[f"差异区域 {len(middle)} 字节，香农熵 {entropy:.2f}"],
            )
        )
    else:
        results.append(
            RuleResult(
                rule_id="unknown-bytes",
                category="unknown",
                confidence="low",
                samples=[f"二进制差异 {len(middle)} 字节，熵 {entropy:.2f}，无已知形态匹配"],
            )
        )
    return results
