"""产物比对：归档级元数据检查 + 文件级内容归因。"""

from __future__ import annotations

from pathlib import Path

from .archives import ArchiveView, Entry, open_archive
from .model import (
    CATEGORY_ABS_PATH,
    CATEGORY_CODE,
    CATEGORY_LOCALE,
    CATEGORY_MISSING,
    CATEGORY_MODE,
    CATEGORY_MTIME,
    CATEGORY_ORDER,
    CATEGORY_OWNER,
    CATEGORY_RANDOM,
    CATEGORY_UNKNOWN,
    ArtifactReport,
    Evidence,
    Finding,
    sha256_bytes,
    sha256_file,
)
from .rules import (
    REMEDIATIONS,
    TITLES,
    BuildContext,
    RuleResult,
    explain_bytes,
    explain_text,
    make_unified_diff,
)

_PREVIEW = 240


def _preview(data: bytes) -> str:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        s = data.decode("utf-8", errors="replace")
    s = s.strip()
    if len(s) > _PREVIEW:
        s = s[:_PREVIEW] + " …<截断>"
    return s


def _finding(
    result: RuleResult,
    location: str,
    evidence: Evidence | None,
    count: int = 1,
) -> Finding:
    return Finding(
        rule_id=result.rule_id,
        category=result.category,
        title=TITLES.get(result.category, result.category),
        location=location,
        remediation=REMEDIATIONS.get(result.category, "请人工确认该差异来源。"),
        confidence=result.confidence,
        count=count,
        evidence=evidence,
    )


def compare_artifact(path_a: Path, path_b: Path, name: str, ctx: BuildContext) -> ArtifactReport:
    view_a = open_archive(path_a)
    view_b = open_archive(path_b)

    report = ArtifactReport(
        name=name,
        kind=view_a.kind,
        size_a=path_a.stat().st_size,
        size_b=path_b.stat().st_size,
        digest_a=sha256_file(path_a),
        digest_b=sha256_file(path_b),
        entries_total=len(view_a.entries),
    )
    if report.raw_equal:
        return report

    raw_findings: list[Finding] = []
    raw_findings += _compare_archive_meta(view_a, view_b)
    raw_findings += _compare_entries(view_a, view_b, name, ctx)
    report.findings = _aggregate(raw_findings)
    return report


# ---------------------------------------------------------------------------
# 归档级：顺序、成员集合、gzip mtime
# ---------------------------------------------------------------------------

def _compare_archive_meta(a: ArchiveView, b: ArchiveView) -> list[Finding]:
    out: list[Finding] = []

    names_a = [n for n in (a.ordered_names or [])]
    names_b = [n for n in (b.ordered_names or [])]
    if names_a and names_b and names_a != names_b:
        if sorted(names_a) == sorted(names_b):
            out.append(
                Finding(
                    rule_id="entry-order",
                    category=CATEGORY_ORDER,
                    title=TITLES["entry-order"],
                    location=f"{a.path} (成员顺序)",
                    remediation=REMEDIATIONS["entry-order"],
                    confidence="high",
                    scope="archive",
                    count=1,
                    evidence=Evidence(
                        a=" → ".join(names_a[:8]),
                        b=" → ".join(names_b[:8]),
                        note=f"成员集合相同（{len(names_a)} 个），仅顺序不同",
                    ),
                )
            )

    set_a, set_b = set(names_a), set(names_b)
    only_a, only_b = sorted(set_a - set_b), sorted(set_b - set_a)
    if only_a or only_b:
        out.append(
            Finding(
                rule_id="missing-entry",
                category=CATEGORY_MISSING,
                title=TITLES["missing-entry"],
                location=f"{a.path} (成员集合)",
                remediation=REMEDIATIONS["missing-entry"],
                confidence="high",
                scope="archive",
                count=len(only_a) + len(only_b),
                evidence=Evidence(
                    a="仅 A 有: " + (", ".join(only_a[:10]) or "无"),
                    b="仅 B 有: " + (", ".join(only_b[:10]) or "无"),
                ),
            )
        )

    if a.gzip_mtime is not None and b.gzip_mtime is not None and a.gzip_mtime != b.gzip_mtime:
        out.append(
            Finding(
                rule_id="gzip-mtime",
                category=CATEGORY_MTIME,
                title=TITLES["gzip-mtime"],
                location=f"{a.path} (gzip 头)",
                remediation=REMEDIATIONS["gzip-mtime"],
                confidence="high",
                scope="raw",
                evidence=Evidence(a=str(a.gzip_mtime), b=str(b.gzip_mtime)),
            )
        )
    return out


# ---------------------------------------------------------------------------
# 成员级：元数据（mtime/属主/权限）+ 内容归因
# ---------------------------------------------------------------------------

def _compare_entries(a: ArchiveView, b: ArchiveView, artifact_name: str, ctx: BuildContext) -> list[Finding]:
    out: list[Finding] = []
    map_a, map_b = a.by_name(), b.by_name()

    for entry_name in sorted(set(map_a) & set(map_b)):
        ea, eb = map_a[entry_name], map_b[entry_name]
        loc = f"{artifact_name}!{entry_name}"

        out += _compare_entry_meta(ea, eb, loc, a.kind)
        if ea.data != eb.data:
            out += _compare_entry_content(ea, eb, loc, artifact_name, ctx)
    return out


def _compare_entry_meta(ea: Entry, eb: Entry, loc: str, kind: str) -> list[Finding]:
    out: list[Finding] = []

    if ea.mtime is not None and eb.mtime is not None and ea.mtime != eb.mtime:
        out.append(
            Finding(
                rule_id="entry-mtime",
                category=CATEGORY_MTIME,
                title=TITLES[CATEGORY_MTIME],
                location=loc,
                remediation=REMEDIATIONS[CATEGORY_MTIME],
                confidence="high",
                evidence=Evidence(a=str(ea.mtime), b=str(eb.mtime), note="成员 mtime"),
            )
        )

    if kind == "tar":
        owner_vals_a = (ea.uid, ea.gid, ea.uname, ea.gname)
        owner_vals_b = (eb.uid, eb.gid, eb.uname, eb.gname)
        if owner_vals_a != owner_vals_b:
            out.append(
                Finding(
                    rule_id="entry-owner",
                    category=CATEGORY_OWNER,
                    title=TITLES["owner"],
                    location=loc,
                    remediation=REMEDIATIONS["owner"],
                    confidence="high",
                    evidence=Evidence(
                        a=f"uid={ea.uid} gid={ea.gid} {ea.uname}/{ea.gname}",
                        b=f"uid={eb.uid} gid={eb.gid} {eb.uname}/{eb.gname}",
                    ),
                )
            )

    if ea.mode is not None and eb.mode is not None and ea.mode != eb.mode:
        out.append(
            Finding(
                rule_id="entry-mode",
                category=CATEGORY_MODE,
                title=TITLES["mode"],
                location=loc,
                remediation=REMEDIATIONS["mode"],
                confidence="high",
                evidence=Evidence(
                    a=oct(ea.mode), b=oct(eb.mode), note="成员权限位"
                ),
            )
        )
    return out


def _compare_entry_content(
    ea: Entry, eb: Entry, loc: str, artifact_name: str, ctx: BuildContext
) -> list[Finding]:
    digest_note = f"A sha256={sha256_bytes(ea.data)[:16]}… B sha256={sha256_bytes(eb.data)[:16]}…"

    try:
        text_a = ea.data.decode("utf-8")
        text_b = eb.data.decode("utf-8")
    except UnicodeDecodeError:
        return _binary_findings(ea, eb, loc, ctx, digest_note)

    expl = explain_text(text_a, text_b, ctx)
    out: list[Finding] = []
    for result in expl.results:
        out.append(
            _finding(
                result,
                loc,
                Evidence(a=_preview(ea.data), b=_preview(eb.data), note=digest_note),
            )
        )

    if not expl.fully_explained:
        # 已知规则解释不了的部分：真实代码差异，附 unified diff
        out.append(
            Finding(
                rule_id="content-diff",
                category=CATEGORY_CODE,
                title=TITLES[CATEGORY_CODE],
                location=loc,
                remediation=REMEDIATIONS[CATEGORY_CODE],
                confidence="high",
                evidence=Evidence(a="", b="", note=digest_note),
                diff=make_unified_diff(
                    text_a, text_b, f"A:{artifact_name}!{ea.name}", f"B:{artifact_name}!{eb.name}"
                ),
            )
        )
    elif not expl.results:
        # 理论上到不了这里（内容不等就应有规则命中），兜底
        out.append(
            Finding(
                rule_id="unknown-text",
                category=CATEGORY_UNKNOWN,
                title="文本差异未命中任何规则",
                location=loc,
                remediation=REMEDIATIONS[CATEGORY_CODE],
                confidence="low",
                evidence=Evidence(a=_preview(ea.data), b=_preview(eb.data), note=digest_note),
            )
        )
    return out


def _binary_findings(
    ea: Entry, eb: Entry, loc: str, ctx: BuildContext, digest_note: str
) -> list[Finding]:
    results = explain_bytes(ea.data, eb.data, ctx)
    out: list[Finding] = []
    for result in results:
        out.append(
            _finding(
                result,
                loc,
                Evidence(a=_preview(ea.data), b=_preview(eb.data), note=digest_note),
            )
        )
    if not results:
        out.append(
            Finding(
                rule_id="unknown-binary",
                category=CATEGORY_UNKNOWN,
                title="二进制差异未命中任何规则",
                location=loc,
                remediation="请人工用反汇编/字节级工具确认差异来源。",
                confidence="low",
                evidence=Evidence(a=_preview(ea.data), b=_preview(eb.data), note=digest_note),
            )
        )
    return out


# ---------------------------------------------------------------------------
# 同类发现聚合：元数据/规则类按 (category, rule_id) 合并，code-diff 保留逐条
# ---------------------------------------------------------------------------

def _aggregate(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str], Finding] = {}
    code_diffs: list[Finding] = []
    order: list[tuple[str, str]] = []

    for f in findings:
        if f.category == CATEGORY_CODE:
            code_diffs.append(f)
            continue
        key = (f.category, f.rule_id)
        if key not in merged:
            merged[key] = f
            order.append(key)
            continue
        m = merged[key]
        m.count += f.count
        locations = m.location.split(", ")
        if f.location not in locations and len(locations) < 8:
            m.location = f"{m.location}, {f.location}"
        # 保留信息量最大的证据
        if f.evidence and m.evidence:
            m.evidence.note = (m.evidence.note or "") + " | " + (f.evidence.note or "")

    return [merged[k] for k in order] + code_diffs
