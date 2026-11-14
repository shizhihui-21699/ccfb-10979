"""评分、可信度结论与报告渲染（文本 / JSON / Markdown）。"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone

from .model import (
    CATEGORY_CODE,
    CATEGORY_MISSING,
    CATEGORY_ORDER,
    CATEGORY_UNKNOWN,
    CATEGORY_TITLES,
    RunReport,
    Verdict,
)

# 每类问题的单条扣分权重；同一类别在后续产物中重复出现只象征性扣分。
# 权重刻意分档：真实代码差异/无法归因（致命）≫ 缺失 > 可修复的非确定源
PENALTY = {
    CATEGORY_CODE: 45,
    CATEGORY_UNKNOWN: 30,
    CATEGORY_MISSING: 20,
    "absolute-path": 8,
    "randomness": 7,
    "timestamp": 6,
    "locale": 5,
    "owner": 4,
    "mode": 3,
    CATEGORY_ORDER: 2,
}


def decide_verdict(report: RunReport) -> None:
    """汇总所有产物发现，打分并给出结论。"""
    notes: list[str] = []
    score = 100
    cats_seen: dict[str, int] = {}

    if not report.build_a.ok or not report.build_b.ok:
        report.verdict = Verdict.ERROR
        report.score = 0
        report.score_notes = ["至少一侧构建失败，无法评估复现性。"]
        return

    for art in report.artifacts:
        if art.raw_equal:
            continue
        for f in art.findings:
            seen = cats_seen.get(f.category, 0)
            weight = PENALTY.get(f.category, 10)
            # 同一类别在首个产物全额扣分，之后只象征性扣分，
            # 避免“同一病因出现在 N 个产物”把分数无脑扣到 0
            deduction = weight if seen == 0 else max(1, weight // 6)
            score -= deduction
            cats_seen[f.category] = seen + 1
            notes.append(
                f"-{deduction} {CATEGORY_TITLES.get(f.category, f.category)}"
                f"（{art.name}，{f.rule_id}，置信度 {f.confidence}）"
            )

    # 未配对的产物（只在一侧出现）按缺失处理
    for rel, side in report.unpaired:
        score -= PENALTY[CATEGORY_MISSING]
        notes.append(f"-{PENALTY[CATEGORY_MISSING]} 产物仅在 {side} 侧出现：{rel}")

    score = max(0, min(100, score))
    report.score = score

    all_cats = set(cats_seen)
    if not report.artifacts:
        report.verdict = Verdict.ERROR
        notes.append("dist 中没有找到任何可比对产物。")
    elif CATEGORY_CODE in all_cats:
        report.verdict = Verdict.NON_REPRODUCIBLE
        notes.append("存在真实代码差异，构建不可复现。")
    elif CATEGORY_UNKNOWN in all_cats:
        report.verdict = Verdict.NON_REPRODUCIBLE
        notes.append("存在无法自动归因的差异，需人工介入，暂不能宣称可复现。")
    elif not all_cats and not report.unpaired:
        report.verdict = Verdict.REPRODUCIBLE
        notes.append("所有产物字节级一致，构建可复现。")
    else:
        report.verdict = Verdict.DETERMINISTIC_WITH_FIXES
        notes.append("差异全部可归因于已知非确定源，按建议修复后可达成字节级复现。")

    report.score_notes = notes


VERDICT_TEXT = {
    Verdict.REPRODUCIBLE: "可信：可复现（字节级一致）",
    Verdict.DETERMINISTIC_WITH_FIXES: "有条件可信：差异均为已知非确定性，修复后可复现",
    Verdict.NON_REPRODUCIBLE: "不可信：存在真实/无法解释的差异，不可宣称可复现",
    Verdict.ERROR: "无法评估：构建失败或无产物",
}


# ---------------------------------------------------------------------------
# 文本报告
# ---------------------------------------------------------------------------

def render_text(report: RunReport) -> str:
    L: list[str] = []
    push = L.append

    push("=" * 78)
    push("可复现构建验证报告")
    push("=" * 78)
    push(f"源码目录   : {report.source}")
    push(f"构建命令   : {report.build_cmd}")
    push(f"工作目录   : {report.workdir}")
    push(f"SDE/epoch  : {report.source_date_epoch}")
    push(f"环境探测   : {'开启（B 侧使用 en_US.UTF-8 / America/New_York）' if report.vary_env else '关闭（两侧环境一致）'}")
    push(f"生成时间   : {report.generated_at}")
    push("")

    push("-" * 78)
    push("构建 A")
    push(f"  目录: {report.build_a.root}")
    push(f"  状态: {'成功' if report.build_a.ok else '失败'} (exit={report.build_a.returncode})")
    push(f"  产物: {len(report.build_a.artifacts)} 个")
    push("-" * 78)
    push("构建 B")
    push(f"  目录: {report.build_b.root}")
    push(f"  状态: {'成功' if report.build_b.ok else '失败'} (exit={report.build_b.returncode})")
    push(f"  产物: {len(report.build_b.artifacts)} 个")
    if not report.build_b.ok:
        push("  错误: " + (report.build_b.error or report.build_b.log[-500:]))
    push("")

    push("-" * 78)
    push("产物级比对")
    push("-" * 78)
    for art in report.artifacts:
        mark = "✓ 字节一致" if art.raw_equal else "✗ 存在差异"
        push(f"[{mark}] {art.name}  ({art.kind}, {art.entries_total} 个成员)")
        push(f"    A sha256: {art.digest_a}")
        if not art.raw_equal:
            push(f"    B sha256: {art.digest_b}")
        if art.findings:
            for f in art.findings:
                push(
                    f"    ├─ [{f.confidence}] {CATEGORY_TITLES.get(f.category, f.category)}"
                    f"  <{f.rule_id}> ×{f.count}"
                )
                push(f"    │    位置: {f.location}")
                if f.evidence and (f.evidence.a or f.evidence.b or f.evidence.note):
                    if f.evidence.a:
                        push(f"    │    A   : {f.evidence.a}")
                    if f.evidence.b:
                        push(f"    │    B   : {f.evidence.b}")
                    if f.evidence.note:
                        push(f"    │    备注: {f.evidence.note}")
                push(f"    │    消除: {f.remediation}")
                if f.diff:
                    push("    │    差异内容（unified diff）:")
                    for line in f.diff.splitlines()[:40]:
                        push(f"    │      {line}")
    for rel, side in report.unpaired:
        push(f"[✗ 未配对] {rel}（仅 {side} 侧存在）")
    push("")

    push("-" * 78)
    push("评分明细")
    push("-" * 78)
    for note in report.score_notes:
        push("  " + note)
    push("")
    push("=" * 78)
    push(f"可信度评分: {report.score}/100")
    push(f"结论: {VERDICT_TEXT[report.verdict]}")
    push("=" * 78)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# JSON 报告
# ---------------------------------------------------------------------------

def render_json(report: RunReport) -> str:
    data = dataclasses.asdict(report)
    data["verdict"] = report.verdict.value
    return json.dumps(data, ensure_ascii=False, indent=2)


def render_markdown(report: RunReport) -> str:
    L: list[str] = []
    L.append("# 可复现构建验证报告")
    L.append("")
    L.append(f"- **结论**: {VERDICT_TEXT[report.verdict]}")
    L.append(f"- **可信度评分**: {report.score}/100")
    L.append(f"- **源码**: `{report.source}`")
    L.append(f"- **构建命令**: `{report.build_cmd}`")
    L.append(f"- **SOURCE_DATE_EPOCH**: {report.source_date_epoch}")
    L.append(f"- **环境探测**: {'开启' if report.vary_env else '关闭'}")
    L.append("")
    L.append("## 产物比对")
    L.append("")
    L.append("| 产物 | 类型 | 结果 | sha256(A) | sha256(B) |")
    L.append("|---|---|---|---|---|")
    for art in report.artifacts:
        status = "✅ 一致" if art.raw_equal else "❌ 差异"
        L.append(
            f"| `{art.name}` | {art.kind} | {status} | `{art.digest_a[:16]}` | "
            f"`{art.digest_b[:16] if not art.raw_equal else '—'}` |"
        )
    L.append("")
    if any(a.findings for a in report.artifacts):
        L.append("## 差异归因")
        L.append("")
        L.append("| 产物 | 类别 | 规则 | 置信度 | 位置 | 消除办法 |")
        L.append("|---|---|---|---|---|---|")
        for art in report.artifacts:
            for f in art.findings:
                L.append(
                    f"| `{art.name}` | {CATEGORY_TITLES.get(f.category, f.category)} "
                    f"| `{f.rule_id}` | {f.confidence} | `{f.location}` | {f.remediation} |"
                )
        L.append("")
    return "\n".join(L)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
