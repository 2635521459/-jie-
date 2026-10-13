"""动态只读工具。实现只此一份；MCP 不得另写读盘逻辑。"""

from __future__ import annotations

import os
from pathlib import Path

from ohscan.locate import read_source_slice

# C/C++ 之外也要能搜到 NAPI / ArkTS 绑定，否则 request 的 JS 调用点经常找不到。
_CODE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".ts", ".ets", ".js"}
_MAX_FILE_CHARS = 8000
_MAX_CALLERS = 20


# 把相对路径限制在 source_root 内；含 .. 或逃出根目录则返回 None。
def resolve_under_root(source_root: Path, rel_path: str) -> Path | None:
    root = source_root.resolve()
    rel = rel_path.replace("\\", "/").lstrip("/")
    if not rel or ".." in Path(rel).parts:
        return None
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path


# 复用静态截段：优先整函数，给模型看告警所在函数体。
def read_function(source_root: Path, rel_path: str, start_line: int) -> dict:
    path = resolve_under_root(source_root, rel_path)
    if path is None or not path.is_file():
        return {"ok": False, "error": "path outside source root or missing"}
    slice_ = read_source_slice(source_root, rel_path.replace("\\", "/"), start_line)
    if not slice_.snippet:
        return {"ok": False, "error": "no snippet"}
    return {
        "ok": True,
        "path": rel_path.replace("\\", "/"),
        "function": slice_.function,
        "start_line": slice_.start_line,
        "end_line": slice_.end_line,
        "snippet": slice_.snippet,
    }


# 读源码根内一个文件的行区间，用来看常量、宏、缓冲区大小等定义。
def read_file(source_root: Path, rel_path: str, start_line: int = 1, end_line: int = 80) -> dict:
    path = resolve_under_root(source_root, rel_path)
    if path is None or not path.is_file():
        return {"ok": False, "error": "path outside source root or missing"}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    lo = max(1, start_line)
    hi = min(len(lines), max(lo, end_line))
    body = "\n".join(f"{i}| {lines[i - 1]}" for i in range(lo, hi + 1))
    if len(body) > _MAX_FILE_CHARS:
        body = body[:_MAX_FILE_CHARS] + "\n..."
    return {"ok": True, "path": rel_path.replace("\\", "/"), "text": body}


# 在源码根内按符号名做文本搜索，先不当精确调用图。
def find_callers(source_root: Path, symbol: str) -> dict:
    name = (symbol or "").strip()
    if not name or len(name) < 3:
        return {"ok": False, "error": "symbol too short"}
    root = source_root.resolve()
    hits: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [n for n in dirnames if n.lower() not in {".git", "out", "prebuilts", "node_modules"}]
        for filename in filenames:
            full = Path(dirpath) / filename
            if full.suffix.lower() not in _CODE_SUFFIXES:
                continue
            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = full.relative_to(root).as_posix()
            for i, line in enumerate(text.splitlines(), start=1):
                if name in line:
                    hits.append({"path": rel, "line": i, "text": line.strip()[:200]})
                    if len(hits) >= _MAX_CALLERS:
                        return {"ok": True, "symbol": name, "hits": hits, "truncated": True}
    return {"ok": True, "symbol": name, "hits": hits, "truncated": False}


# 给模型看的工具清单（OpenAI tools 格式）。
def tool_specs() -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": "read_function",
                "description": "读取命中处所在的整函数（优先完整函数体，供重建触发链）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                    },
                    "required": ["path", "start_line"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "读取源文件行区间：常量/宏/缓冲区大小定义，不限于 AREA。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_callers",
                "description": "按函数名或汇点符号搜索调用/出现位置，用于补调用链。",
                "parameters": {
                    "type": "object",
                    "properties": {"symbol": {"type": "string"}},
                    "required": ["symbol"],
                },
            },
        },
    ]


# 按名字分发；未知工具返回 error，不抛给模型循环。
def dispatch(source_root: Path, name: str, arguments: dict) -> dict:
    if name == "read_function":
        return read_function(
            source_root,
            str(arguments.get("path") or ""),
            int(arguments.get("start_line") or 1),
        )
    if name == "read_file":
        return read_file(
            source_root,
            str(arguments.get("path") or ""),
            int(arguments.get("start_line") or 1),
            int(arguments.get("end_line") or 80),
        )
    if name == "find_callers":
        return find_callers(source_root, str(arguments.get("symbol") or ""))
    return {"ok": False, "error": f"unknown tool: {name}"}
