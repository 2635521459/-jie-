"""检测引擎适配器基类。

规划：
- 每个引擎只负责「扫 + 写成 raw/<name>.jsonl」，禁止直接改 ctx.findings。
- 统一在这里落盘，是为了 merge 阶段可以对齐多引擎结果。
- 新引擎：继承 Engine，填 name，在 pipeline 注册，规则放到 knowledge/rules/。当前只接通 Semgrep。
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ohscan.models.finding import Finding
from ohscan.pipeline import ScanContext


class Engine(ABC):
    name: str

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        """返回原始告警。不要在这里做 CWE/CVE 最终判定。"""


def run_engine(engine: Engine, ctx: ScanContext) -> None:
    findings = engine.scan(ctx)
    out = ctx.raw_dir / f"{engine.name}.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(finding.model_dump_json() + "\n")
