"""CWE 来自规则；CVE 只做指纹对齐，禁止猜测。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ohscan.models.finding import Finding

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CVE_FILE = _REPO_ROOT / "knowledge" / "cve" / "fingerprints.json"
# 只允许引擎已经实现的 CWE。路径遍历/命令注入/格式串/无界复制是 medium；
# 190/200/415 是 low，研判会先丢掉，这里仍然拒绝把别的编号贴到这些类型上。
_MATCHABLE_CWE = frozenset(
    {
        "CWE-22",
        "CWE-78",
        "CWE-120",
        "CWE-134",
        "CWE-242",
        "CWE-190",
        "CWE-200",
        "CWE-415",
    }
)
_SOURCE_SUFFIX = (".c", ".cc", ".cpp", ".h", ".hpp", ".java")
_FUNC_NAME = re.compile(r"[A-Za-z_][\w:]*")

CWE_FALLBACK = {
    "buffer": ("CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer"),
    "uaf": ("CWE-416", "Use After Free"),
    "overflow": ("CWE-190", "Integer Overflow or Wraparound"),
}


# 规则没带 CWE 时按标题补一层；CVE 必须指纹对齐，路径子串单独不够。
def run_enrich(ctx: ScanContext) -> None:
    fingerprints = _load_fingerprints()
    for finding in ctx.findings:
        if not finding.cwe_id:
            title = finding.title.lower()
            for key, (cwe_id, cwe_name) in CWE_FALLBACK.items():
                if key in title:
                    finding.cwe_id = cwe_id
                    finding.cwe_name = cwe_name
                    break
        if finding.cve_ids:
            continue
        matched = _match_fingerprint(finding, fingerprints)
        if not matched:
            continue
        # 编号和公告版本一起抄；没有命中时不得从 CWE 推断 CVE。
        finding.cve_ids = [str(matched["cve_id"]).strip()]
        versions = [
            str(v).strip()
            for v in (matched.get("affected_versions") or [])
            if str(v).strip()
        ]
        if versions:
            finding.affected_versions = versions
            finding.extra["version_basis"] = "cve_advisory"


# 文件、函数、已实现 CWE 三者都要命中。缺一项、或两行同时命中，都不抄编号。
def _match_fingerprint(finding: Finding, fingerprints: list[dict]) -> dict | None:
    rel = finding.locations[0].path.replace("\\", "/") if finding.locations else ""
    func = ""
    if finding.locations and finding.locations[0].function:
        func = finding.locations[0].function
    cwe = finding.cwe_id or ""
    hits = [
        item
        for item in fingerprints
        if _item_matches(item, rel, func, cwe)
    ]
    if len(hits) != 1:
        return None
    return hits[0]


def _item_matches(item: dict, rel: str, func: str, cwe: str) -> bool:
    if not _usable_item(item):
        return False
    needle = str(item.get("path_contains") or "").replace("\\", "/").strip()
    want_fn = str(item.get("function") or "").strip()
    want_cwe = str(item.get("cwe_id") or "").strip()
    return needle in rel and want_fn in func and want_cwe == cwe


def _usable_item(item: dict) -> bool:
    cve = str(item.get("cve_id") or "").strip()
    needle = str(item.get("path_contains") or "").replace("\\", "/").strip()
    func = str(item.get("function") or "").strip()
    cwe = str(item.get("cwe_id") or "").strip()
    if not cve or cwe not in _MATCHABLE_CWE:
        return False
    if not needle.endswith(_SOURCE_SUFFIX):
        return False
    return _FUNC_NAME.fullmatch(func) is not None


# 指纹表不存在或 items 为空时返回 []，调用方不得据此编造编号。
def _load_fingerprints() -> list[dict]:
    if not _CVE_FILE.exists():
        return []
    data = json.loads(_CVE_FILE.read_text(encoding="utf-8"))
    return data.get("items") or []
