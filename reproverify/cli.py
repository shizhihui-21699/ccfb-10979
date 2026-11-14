"""命令行入口。

用法示例：
  python -m reproverify --source examples/demo_app \
      --build-cmd 'python build_buggy.py' --workdir .rv-work
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

from .builder import BuildConfig, run_double_build
from .compare import compare_artifact
from .model import RunReport, Verdict
from .report import decide_verdict, now_iso, render_json, render_markdown, render_text

# 固定的默认 epoch（2023-11-14T22:13:20Z），保证工具本身的多次运行可复现
DEFAULT_EPOCH = 1_700_000_000


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reproverify",
        description="客户端安装包可复现构建验证工具：双目录构建 + 文件级比对 + 非确定性归因",
    )
    p.add_argument("--source", required=True, type=Path, help="源码目录（同一份源码会被复制两份）")
    p.add_argument("--build-cmd", required=True, help="在源码目录中执行的构建命令（shell）")
    p.add_argument(
        "--dist-subdir",
        default="dist",
        help="构建产物所在的子目录（相对源码根，默认 dist）",
    )
    p.add_argument("--workdir", type=Path, default=None, help="工作目录，默认系统临时目录")
    p.add_argument(
        "--epoch",
        type=int,
        default=DEFAULT_EPOCH,
        help=f"注入的 SOURCE_DATE_EPOCH，默认 {DEFAULT_EPOCH}",
    )
    p.add_argument(
        "--vary-env",
        action="store_true",
        help="让 B 侧使用不同 locale/时区（en_US.UTF-8 / America/New_York），探测 locale 类非确定性",
    )
    p.add_argument("--timeout", type=int, default=600, help="单侧构建超时秒数，默认 600")
    p.add_argument("--keep", action="store_true", help="保留工作目录便于事后检查")
    p.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="报告格式，默认 text",
    )
    p.add_argument("--output", type=Path, default=None, help="报告输出文件，默认 stdout")
    return p


def _pair_artifacts(info_a, info_b, workdir: Path, dist: str):
    """按 dist 内相对路径配对产物，返回 (配对列表, 未配对列表)。"""
    set_a, set_b = set(info_a.artifacts), set(info_b.artifacts)
    paired = sorted(set_a & set_b)
    unpaired = [(n, "A") for n in sorted(set_a - set_b)] + [
        (n, "B") for n in sorted(set_b - set_a)
    ]
    paths = []
    root_a = workdir / "build-a" / "src" / dist
    root_b = workdir / "build-b" / "src" / dist
    for rel in paired:
        paths.append((rel, root_a / rel, root_b / rel))
    return paths, unpaired


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source = args.source.resolve()
    if not source.is_dir():
        print(f"错误：源码目录不存在: {source}", file=sys.stderr)
        return 2

    if args.workdir:
        workdir = args.workdir.resolve()
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir(parents=True)
        cleanup = False
    else:
        workdir = Path(tempfile.mkdtemp(prefix="reproverify-"))
        cleanup = not args.keep

    try:
        cfg = BuildConfig(
            source=source,
            workdir=workdir,
            build_cmd=args.build_cmd,
            dist_subdir=args.dist_subdir,
            epoch=args.epoch,
            vary_env=args.vary_env,
            timeout=args.timeout,
            keep=args.keep,
        )
        info_a, info_b, ctx = run_double_build(cfg)

        report = RunReport(
            source=str(source),
            build_cmd=args.build_cmd,
            workdir=str(workdir),
            vary_env=args.vary_env,
            source_date_epoch=args.epoch,
            build_a=info_a,
            build_b=info_b,
            generated_at=now_iso(),
        )

        if info_a.ok and info_b.ok:
            paired, unpaired = _pair_artifacts(info_a, info_b, workdir, args.dist_subdir)
            report.unpaired = unpaired
            for rel, pa, pb in paired:
                report.artifacts.append(compare_artifact(pa, pb, rel, ctx))

        decide_verdict(report)

        renderer = {
            "text": render_text,
            "json": render_json,
            "markdown": render_markdown,
        }[args.format]
        out = renderer(report)
        if args.output:
            args.output.write_text(out, encoding="utf-8")
        else:
            print(out)

        if report.verdict == Verdict.ERROR:
            return 2
        if report.verdict == Verdict.NON_REPRODUCIBLE:
            return 1
        return 0
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
