"""静态 DAG：共享状态、编排、调度。改编排只改 PIPELINE，不要在 stage 文件里互相调用。

引擎在 index 之后跑 Semgrep；研判之后 enrich 与 impact 并行；report 写出 JSON。
动态第二裁判挂在 report 之后：只读已有告警，未配模型则跳过。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from ohscan.models.finding import Finding, ScanRequest

StageFn = Callable[["ScanContext"], None]


@dataclass
class ScanContext:
    request: ScanRequest
    work_dir: Path
    findings: list[Finding] = field(default_factory=list)
    rejected: list[Finding] = field(default_factory=list)
    stage_metrics: dict[str, dict[str, float]] = field(default_factory=dict)

    @property
    def raw_dir(self) -> Path:
        path = self.work_dir / "raw"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def report_dir(self) -> Path:
        path = self.work_dir / "report"
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass(frozen=True)
class StageSpec:
    name: str
    requires: tuple[str, ...]
    optional: bool = False
    parallel_group: str | None = None


PIPELINE: tuple[StageSpec, ...] = (
    StageSpec("ingest", ()),
    StageSpec("index", ("ingest",)),
    StageSpec("semgrep", ("index",), parallel_group="engines"),
    StageSpec("merge", ("semgrep",)),
    StageSpec("triage", ("merge",)),
    StageSpec("enrich", ("triage",), parallel_group="post"),
    StageSpec("impact", ("triage",), parallel_group="post"),
    StageSpec("poc", ("enrich", "impact"), optional=True, parallel_group="verify"),
    StageSpec("fix", ("enrich", "impact"), optional=True, parallel_group="verify"),
    StageSpec("report", ("enrich", "impact", "poc", "fix")),
    # 第二裁判：依赖已经落盘的 report.json。optional：模型失败不推翻静态结论。
    StageSpec("review", ("report",), optional=True),
)


def enabled_stages(
    enabled_engines: list[str],
    enable_poc: bool,
    enable_fix: bool,
    enable_review: bool = True,
) -> list[StageSpec]:
    engines = set(enabled_engines)
    selected: list[StageSpec] = []
    for spec in PIPELINE:
        if spec.parallel_group == "engines" and spec.name not in engines:
            continue
        if spec.name == "poc" and not enable_poc:
            continue
        if spec.name == "fix" and not enable_fix:
            continue
        if spec.name == "review" and not enable_review:
            continue
        selected.append(spec)
    return selected


class PipelineRunner:
    def __init__(self, stages: dict[str, StageFn]) -> None:
        self._stages = stages

    def run(self, ctx: ScanContext) -> ScanContext:
        ctx.work_dir.mkdir(parents=True, exist_ok=True)
        selected = enabled_stages(
            ctx.request.engines,
            ctx.request.enable_poc,
            ctx.request.enable_fix,
            ctx.request.enable_review,
        )
        selected_names = {spec.name for spec in selected}
        done: set[str] = set()
        pending = list(selected)
        while pending:
            ready = [
                spec
                for spec in pending
                if _deps_satisfied(spec, done, selected_names)
            ]
            if not ready:
                missing = [spec.name for spec in pending]
                raise RuntimeError(f"pipeline stalled, pending={missing}")
            groups: dict[str, list[StageSpec]] = {}
            serial: list[StageSpec] = []
            for spec in ready:
                if spec.parallel_group:
                    groups.setdefault(spec.parallel_group, []).append(spec)
                else:
                    serial.append(spec)
            for spec in serial:
                self._run_one(spec, ctx)
                done.add(spec.name)
                pending = [s for s in pending if s.name != spec.name]
            for batch in groups.values():
                self._run_parallel(batch, ctx)
                for spec in batch:
                    done.add(spec.name)
                names = {spec.name for spec in batch}
                pending = [s for s in pending if s.name not in names]
        self._write_findings(ctx)
        return ctx

    def _run_one(self, spec: StageSpec, ctx: ScanContext) -> None:
        fn = self._stages.get(spec.name)
        if fn is None:
            if spec.optional:
                return
            raise KeyError(f"stage not registered: {spec.name}")
        started = time.perf_counter()
        try:
            fn(ctx)
        except Exception:
            if not spec.optional:
                raise
        elapsed = time.perf_counter() - started
        ctx.stage_metrics[spec.name] = {"seconds": round(elapsed, 3)}
        _write_progress(ctx.work_dir, spec.name, elapsed)

    def _run_parallel(self, batch: list[StageSpec], ctx: ScanContext) -> None:
        if len(batch) == 1:
            self._run_one(batch[0], ctx)
            return
        with ThreadPoolExecutor(max_workers=len(batch)) as pool:
            futures = {pool.submit(self._run_one, spec, ctx): spec for spec in batch}
            for future in as_completed(futures):
                future.result()

    def _write_findings(self, ctx: ScanContext) -> None:
        path = ctx.work_dir / "findings.jsonl"
        # report 已写过则跳过，避免和第二套序列化打架。
        if not path.exists():
            from ohscan.deliver import dump_finding_line

            with path.open("w", encoding="utf-8") as handle:
                for finding in ctx.findings:
                    handle.write(dump_finding_line(finding) + "\n")
        metrics = ctx.work_dir / "metrics.json"
        metrics.write_text(
            json.dumps(
                {
                    "stages": ctx.stage_metrics,
                    "accepted": len(ctx.findings),
                    "rejected": len(ctx.rejected),
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def _deps_satisfied(spec: StageSpec, done: set[str], selected_names: set[str]) -> bool:
    required = [dep for dep in spec.requires if dep in selected_names]
    return all(dep in done for dep in required)


def _write_progress(work_dir: Path, stage: str, elapsed: float) -> None:
    path = work_dir / "progress.json"
    payload = {"stage": stage, "elapsed_seconds": elapsed}
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["stage"] = stage
            payload["elapsed_seconds"] = elapsed
        except json.JSONDecodeError:
            pass
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# 延迟 import stage，避免 pipeline ↔ locate/deliver 循环。
def build_runner() -> PipelineRunner:
    from ohscan.deliver import run_fix, run_report
    from ohscan.dynamic.stage import run_review
    from ohscan.engines import run_merge, run_semgrep
    from ohscan.enrich import run_enrich
    from ohscan.locate import run_impact, run_index, run_ingest
    from ohscan.poc import run_poc
    from ohscan.triage import run_triage

    return PipelineRunner(
        {
            "ingest": run_ingest,
            "index": run_index,
            "semgrep": run_semgrep,
            "merge": run_merge,
            "triage": run_triage,
            "enrich": run_enrich,
            "impact": run_impact,
            "poc": run_poc,
            "fix": run_fix,
            "report": run_report,
            "review": run_review,
        }
    )


def run_scan(ctx: ScanContext) -> ScanContext:
    """CLI 与 JobRunner 的唯一入口。"""
    return build_runner().run(ctx)
