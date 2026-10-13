"""本地预取卷宗：在调模型之前固定跑工具，结果可缓存。

模型不再当调度器。tools_used 记 prefetch:* ，评委能看到工具确实跑过。
不编译、不上设备、不写利用。
"""

from __future__ import annotations

from pathlib import Path

from ohscan.dynamic.tools import find_callers, read_file, read_function


class ToolCache:
    """同一次 review 里，同一符号/函数只读盘一次。"""

    def __init__(self) -> None:
        self.functions: dict[tuple[str, int], dict] = {}
        self.callers: dict[str, dict] = {}
        self.files: dict[tuple[str, int, int], dict] = {}

    def read_function(self, root: Path, rel: str, start_line: int) -> dict:
        key = (rel.replace("\\", "/"), int(start_line))
        if key not in self.functions:
            self.functions[key] = read_function(root, key[0], key[1])
        return self.functions[key]

    def find_callers(self, root: Path, symbol: str) -> dict:
        name = (symbol or "").strip()
        if not name:
            return {"ok": False, "error": "empty symbol"}
        if name not in self.callers:
            self.callers[name] = find_callers(root, name)
        return self.callers[name]

    def read_file(self, root: Path, rel: str, start: int = 1, end: int = 120) -> dict:
        key = (rel.replace("\\", "/"), int(start), int(end))
        if key not in self.files:
            self.files[key] = read_file(root, key[0], key[1], key[2])
        return self.files[key]


# PathUtils::CheckBelongAppBaseDir -> CheckBelongAppBaseDir，便于搜调用点。
def _short_symbol(function: str | None) -> str:
    text = (function or "").strip()
    if not text:
        return ""
    return text.split("::")[-1].split(".")[-1]


# 固定三件套：整函数、调用点、同文件开头的常量/宏。
def prefetch_dossier(source_root: Path, finding: dict, cache: ToolCache) -> tuple[dict, list[str]]:
    loc = (finding.get("locations") or [{}])[0]
    rel = str(loc.get("path") or "").replace("\\", "/")
    start = int(loc.get("start_line") or 1)
    used: list[str] = []

    hit = cache.read_function(source_root, rel, start)
    used.append("prefetch:read_function")

    symbol = _short_symbol(hit.get("function") or loc.get("function"))
    callers: dict = {"ok": False, "error": "no function name"}
    if symbol:
        callers = cache.find_callers(source_root, symbol)
        used.append("prefetch:find_callers")

    # 同文件前 120 行通常有 AREA1/缓冲区大小；不够时模型仍可再 read_file。
    file_head: dict = {"ok": False, "error": "missing path"}
    if rel:
        file_head = cache.read_file(source_root, rel, 1, 120)
        used.append("prefetch:read_file")

    poc = (finding.get("extra") or {}).get("poc") or {}
    extra = finding.get("extra") or {}
    dossier = {
        "note": "以下由本地工具预取，不是模型想象，也不是设备上的利用。",
        "hit_function": hit,
        "callers": callers,
        "file_head": file_head,
        "poc": {
            "kind": poc.get("kind") or extra.get("poc_kind"),
            "steps": poc.get("steps") or [],
            "note": poc.get("note") or "PoC 是本机 CWE 演示，不得当成已在设备复现。",
        },
    }
    return dossier, used
