"""端到端：真实执行示例项目的双构建并验证归因结论。"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reproverify.builder import BuildConfig, run_double_build
from reproverify.compare import compare_artifact
from reproverify.model import (
    CATEGORY_ABS_PATH,
    CATEGORY_LOCALE,
    CATEGORY_MTIME,
    CATEGORY_ORDER,
    CATEGORY_OWNER,
    CATEGORY_RANDOM,
    CATEGORY_CODE,
    Verdict,
)
from reproverify.report import decide_verdict
from reproverify.model import RunReport
from reproverify.report import now_iso

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo_app"


def _run_demo(script: str, workdir: Path, vary_env: bool):
    cfg = BuildConfig(
        source=DEMO,
        workdir=workdir,
        build_cmd=f'"{sys.executable}" {script}',
        dist_subdir="dist",
        epoch=1_700_000_000,
        vary_env=vary_env,
        timeout=120,
        keep=False,
    )
    info_a, info_b, ctx = run_double_build(cfg)
    self_fail = None
    if not info_a.ok or not info_b.ok:
        raise AssertionError(
            f"构建失败 A(ok={info_a.ok}) B(ok={info_b.ok})\n{info_a.log}\n{info_b.log}"
        )

    report = RunReport(
        source=str(DEMO),
        build_cmd=script,
        workdir=str(workdir),
        vary_env=vary_env,
        source_date_epoch=1_700_000_000,
        build_a=info_a,
        build_b=info_b,
        generated_at=now_iso(),
    )
    common = sorted(set(info_a.artifacts) & set(info_b.artifacts))
    root_a = workdir / "build-a" / "src" / "dist"
    root_b = workdir / "build-b" / "src" / "dist"
    for rel in common:
        report.artifacts.append(compare_artifact(root_a / rel, root_b / rel, rel, ctx))
    decide_verdict(report)
    return report


class BuggyBuildE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = Path(tempfile.mkdtemp(prefix="rv-e2e-buggy-"))
        cls.report = _run_demo("build_buggy.py", cls.workdir, vary_env=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _all_categories(self):
        return {f.category for art in self.report.artifacts for f in art.findings}

    def test_three_artifacts_paired_and_differ(self):
        names = {a.name for a in self.report.artifacts}
        self.assertEqual(
            names,
            {
                "demo_app-1.4.2-py3-none-any.whl",
                "demo_app-portable.zip",
                "demo_app.tar.gz",
            },
        )
        self.assertTrue(all(not a.raw_equal for a in self.report.artifacts))

    def test_all_four_planted_sources_attributed(self):
        cats = self._all_categories()
        # 四类埋雷必须全部认出
        self.assertIn(CATEGORY_ABS_PATH, cats)
        self.assertIn(CATEGORY_MTIME, cats)
        self.assertIn(CATEGORY_RANDOM, cats)
        self.assertIn(CATEGORY_LOCALE, cats)

    def test_archive_order_detected(self):
        self.assertIn(CATEGORY_ORDER, self._all_categories())

    def test_tar_owner_detected(self):
        self.assertIn(CATEGORY_OWNER, self._all_categories())

    def test_no_false_code_diff(self):
        # 所有差异都应能归因，不能误报真实代码差异
        self.assertNotIn(CATEGORY_CODE, self._all_categories())

    def test_verdict_deterministic_with_fixes(self):
        self.assertEqual(self.report.verdict, Verdict.DETERMINISTIC_WITH_FIXES)
        self.assertGreater(self.report.score, 0)
        self.assertLess(self.report.score, 100)

    def test_gzip_mtime_detection_logic(self):
        # gzip mtime 归因逻辑用确定性构造验证：真实构建在同一秒内完成时
        # 两侧 mtime 可能恰好相等（现代 Python gzip 写秒级时间戳），
        # 这里直接构造两个 mtime 不同的 tar.gz，确认工具能识别
        import gzip
        import io
        import tarfile
        import tempfile
        from pathlib import Path
        from reproverify.archives import open_archive
        from reproverify.compare import _compare_archive_meta

        tmp = Path(tempfile.mkdtemp())
        paths = []
        for mtime in (1700000000, 1700000999):
            p = tmp / f"pkg-{mtime}.tar.gz"
            with gzip.GzipFile(p, "wb", mtime=mtime) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tf:
                    info = tarfile.TarInfo("f.txt")
                    data = b"same"
                    info.size = len(data)
                    info.mtime = mtime
                    tf.addfile(info, io.BytesIO(data))
            paths.append(p)
        findings = _compare_archive_meta(open_archive(paths[0]), open_archive(paths[1]))
        self.assertIn("gzip-mtime", {f.rule_id for f in findings})

    def test_every_finding_has_remediation(self):
        for art in self.report.artifacts:
            for f in art.findings:
                self.assertTrue(f.remediation.strip(), f"{f.rule_id} 缺少消除建议")


class FixedBuildE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = Path(tempfile.mkdtemp(prefix="rv-e2e-fixed-"))
        cls.report = _run_demo("build_fixed.py", cls.workdir, vary_env=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_all_artifacts_byte_identical(self):
        self.assertTrue(self.report.artifacts, "应当配对到产物")
        for art in self.report.artifacts:
            self.assertTrue(art.raw_equal, f"{art.name} 未做到字节级一致")
            self.assertEqual(art.findings, [])

    def test_verdict_reproducible_full_score(self):
        self.assertEqual(self.report.verdict, Verdict.REPRODUCIBLE)
        self.assertEqual(self.report.score, 100)


class CodeDiffDetectionTests(unittest.TestCase):
    """在源码副本里制造一次真实代码改动，验证 code-diff 不被噪声规则吞掉。"""

    def test_modified_source_surfaces_code_diff(self):
        workdir = Path(tempfile.mkdtemp(prefix="rv-e2e-code-"))
        try:
            report = _run_demo("build_buggy.py", workdir, vary_env=False)
            # 直接篡改 B 侧源码后重新构建 B，再比对
            src_b = workdir / "build-b" / "src" / "demo_app" / "core.py"
            src_b.write_text(src_b.read_text() + "\n# real change\n")
            subprocess.run(
                [sys.executable, "build_buggy.py"],
                cwd=workdir / "build-b" / "src",
                env=report.build_b.env,
                check=True,
            )
            from reproverify.rules import BuildContext

            ctx = BuildContext(
                root_a=report.build_a.root,
                root_b=report.build_b.root,
                build_started=report.build_a.started_at,
                build_finished=report.build_b.finished_at,
                epoch=1_700_000_000,
            )
            dist_a = workdir / "build-a" / "src" / "dist"
            dist_b = workdir / "build-b" / "src" / "dist"
            art = compare_artifact(
                dist_a / "demo_app-portable.zip",
                dist_b / "demo_app-portable.zip",
                "demo_app-portable.zip",
                ctx,
            )
            cats = {f.category for f in art.findings}
            self.assertIn(CATEGORY_CODE, cats)
            diff = next(f for f in art.findings if f.category == CATEGORY_CODE)
            self.assertIn("real change", diff.diff)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class BuildFailureTests(unittest.TestCase):
    def test_failed_build_returns_error_verdict_and_exit2(self):
        from reproverify.cli import run as cli_run

        workdir = Path(tempfile.mkdtemp(prefix="rv-e2e-fail-"))
        try:
            rc = cli_run(
                [
                    "--source", str(DEMO),
                    "--build-cmd", "exit 7",
                    "--workdir", str(workdir),
                    "--format", "json",
                ]
            )
            self.assertEqual(rc, 2)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_missing_source_returns_exit2(self):
        from reproverify.cli import run as cli_run

        rc = cli_run(["--source", "/no/such/dir/xyz", "--build-cmd", "echo hi"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
