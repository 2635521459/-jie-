"""多引擎告警对齐。这是「检测」和「研判」的分界。

规划：
- 现在按 path:line:cwe/title 去重，并把 engines 列表合并（融合计分要用）。
- 下一步：同一 sink 不同行号做模糊合并；冲突时保留更高 confidence。
"""

from __future__ import annotations

import json

from ohscan.models.finding import Finding
from ohscan.pipeline import ScanContext

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _confidence_rank(finding: Finding) -> int:
    raw = finding.confidence.value if hasattr(finding.confidence, "value") else finding.confidence
    return _CONFIDENCE_RANK.get(str(raw), 1)


def run_merge(ctx: ScanContext) -> None:
    merged: dict[str, Finding] = {}
    for path in sorted(ctx.raw_dir.glob("*.jsonl")):
        engine = path.stem
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            finding = Finding.model_validate_json(line)
            if engine not in finding.engines:
                finding.engines.append(engine)
            key = _dedup_key(finding)
            existing = merged.get(key)
            if existing is None:
                merged[key] = finding
            else:
                engines = sorted(set(existing.engines + finding.engines))
                if _confidence_rank(finding) > _confidence_rank(existing):
                    finding.engines = engines
                    merged[key] = finding
                else:
                    existing.engines = engines
    ctx.findings = list(merged.values())
    out = ctx.work_dir / "merged.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for finding in ctx.findings:
            handle.write(finding.model_dump_json() + "\n")
    (ctx.raw_dir / "merge_meta.json").write_text(
        json.dumps({"count": len(ctx.findings)}, indent=2),
        encoding="utf-8",
    )


def _dedup_key(finding: Finding) -> str:
    loc = finding.locations[0] if finding.locations else None
    if loc:
        return f"{loc.path}:{loc.start_line}:{finding.cwe_id or finding.title}"
    return finding.id
