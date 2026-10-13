"""DAG 节点 review：读刚写出的 report.json，跑第二裁判，再写回 JSON/Markdown。

不发现新漏洞。不编造 CVE。不把 poc_status 写成 verified。
未配模型、正式告警和低置信度拒绝项都没有、或缺少 report.json 时直接返回，扫描仍算成功。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from ohscan.models.finding import Finding

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext


# 静态报告落盘之后才调用。模型只注释已有告警。
def run_review(ctx: ScanContext) -> None:
    report_json = ctx.work_dir / "report" / "report.json"
    if not report_json.is_file():
        return
    # 正式告警和低置信度拒绝项都没有时，不建客户端。
    if not ctx.findings and not _has_low_confidence(ctx.work_dir / "rejected.jsonl"):
        return

    from ohscan.dynamic.config import config_ready, load_config
    from ohscan.dynamic.runtime import run_dynamic

    cfg = load_config()
    if not config_ready(cfg):
        # 评委没配密钥时仍要能出 Semgrep 报告。
        slot = ctx.stage_metrics.setdefault("review", {})
        slot["skipped"] = True
        slot["reason"] = "dynamic disabled or model not configured"
        return

    run_dynamic(report_json, config=cfg)
    if ctx.findings:
        _reload_findings(ctx, report_json)


def _has_low_confidence(path: Path) -> bool:
    if not path.is_file():
        return False
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("fp_reason") == "below confidence threshold":
            return True
    return False


# 模型可能改 summary / extra.dynamic；把磁盘上的报告同步回内存。
def _reload_findings(ctx: ScanContext, report_json: Path) -> None:
    doc = json.loads(report_json.read_text(encoding="utf-8"))
    loaded: list[Finding] = []
    for item in doc.get("findings") or []:
        if isinstance(item, dict):
            loaded.append(Finding.model_validate(item))
    ctx.findings = loaded
