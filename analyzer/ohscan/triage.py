"""研判：静态告警 -> 可上报安全漏洞。准确性主要靠这一层。"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ohscan.models.finding import Confidence

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext

_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

# 这些路径里的命中默认不当安全漏洞（赛题：少把测试当洞）
_SKIP_PARTS = (
    "/test/",
    "/tests/",
    "/example/",
    "/examples/",
    "/unittest/",
    "/moduletest/",
    "/fuzztest/",
    "/fuzz/",
)

# 截段命中行形如 ">  344|     if (...)"; 闸门只读这一行，避免同函数里的 FILE_PREFIX 误杀 AREA*
_HIT_LINE = re.compile(r"^>\s*\d+\|\s*(.*)$", re.M)

# find('/') / find("./")：绝对路径或当前目录判断，不是沙箱边界
_ABS_OR_DOT_FIND = re.compile(
    r"""\.(?:find|rfind)\s*\(\s*(['"]/['"]|['"]\./['"])\s*\)""",
)

# FILE_PREFIX 等在 OH 里是 file://、internal://、./ 分流；不匹配 AREA1 或 DIR_PREFIX
_URI_PREFIX_NAME = re.compile(
    r"\.(?:find|rfind)\s*\(\s*"
    r"(?:FILE_PREFIX|INTERNAL_PREFIX|CURRENT_PREFIX|HTTP_PREFIX|HTTPS_PREFIX|"
    r"CONTENT_PREFIX|DATASHARE_PREFIX|FD_PREFIX|URI_PREFIX|SCHEME_PREFIX|"
    r"[A-Za-z_]\w*SCHEME)\b",
    re.I,
)

# argv 形式的 execv/execvp 是 system() 的推荐替代；无污点不能当 CWE-78。
_ARGV_EXEC = re.compile(r"\b(?:execv|execvp|execve|execvpe)\s*\(")


def run_triage(ctx: ScanContext) -> None:
    accepted = []
    rejected = []
    threshold = _RANK[ctx.request.min_confidence]
    for finding in ctx.findings:
        reason = _reject_reason(finding, threshold)
        if reason:
            finding.fp_reason = reason
            rejected.append(finding)
            continue
        accepted.append(finding)
    ctx.findings = accepted
    ctx.rejected = rejected
    _dump(ctx.work_dir / "accepted.jsonl", accepted)
    _dump(ctx.work_dir / "rejected.jsonl", rejected)


def _reject_reason(finding, threshold: int) -> str | None:
    if _RANK[finding.confidence] < threshold:
        return "below confidence threshold"
    if not finding.locations:
        return "missing source location"
    path = finding.locations[0].path.replace("\\", "/").lower()
    if any(part in f"/{path}/" or part in path for part in _SKIP_PARTS):
        return "test or fuzz path"
    return _reject_path_find_fp(finding) or _reject_argv_exec_fp(finding)


def _reject_path_find_fp(finding) -> str | None:
    sink = (finding.sink or finding.title or "").lower()
    if sink != "oh.path-find-prefix":
        return None
    line = _hit_source_line(finding.locations[0].snippet)
    if not line:
        return None
    if _ABS_OR_DOT_FIND.search(line):
        return "absolute or relative path discriminator, not a directory boundary"
    if _URI_PREFIX_NAME.search(line):
        return "URI or scheme prefix dispatch, not a directory boundary"
    return None


# argv 形式的 exec 没有污点时不是 shell 注入；appspawn 拉起进程会误报。
def _reject_argv_exec_fp(finding) -> str | None:
    sink = (finding.sink or finding.title or "").lower()
    if sink != "oh.exec-command":
        return None
    loc = finding.locations[0]
    line = _hit_source_line(loc.snippet) or (loc.snippet or "")
    if _ARGV_EXEC.search(line):
        return "argv exec is not shell injection without taint"
    return None


def _hit_source_line(snippet: str | None) -> str:
    if not snippet:
        return ""
    match = _HIT_LINE.search(snippet)
    return match.group(1) if match else ""


def _dump(path, findings) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(finding.model_dump_json() + "\n")
