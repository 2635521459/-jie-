"""静态前置：接入源码、索引文件、子系统归属、函数截取、影响范围回填。

不扫描漏洞。引擎只消费这里写出的 file_index / 截段，不要再自己遍历仓库。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext

_REPO_ROOT = Path(__file__).resolve().parents[2]
_YAML_PATH = _REPO_ROOT / "knowledge" / "oh_modules.yml"

# 引擎真正会读的语言；ArkTS 用 .ets
CODE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".ts", ".ets"}

# 构建产物 / 依赖，不应进入漏洞扫描面
SKIP_DIRS = {
    ".git",
    ".repo",
    ".svn",
    "__pycache__",
    "node_modules",
    "out",
    "prebuilts",
    "artifacts",
}

# 全仓保护上限；真正缩小范围靠 subsystems / 时间窗增量
MAX_FILES = 20000

# 找不到函数边界时，命中行上下各留这些行。
_FALLBACK_CONTEXT = 12
_MAX_FUNC_LINES = 280
_SIG_LOOKBACK = 120
_BAD_SNIPPETS = {"requires login", "login required", ""}
_CTRL = {"if", "else", "for", "while", "switch", "catch", "return", "sizeof"}
_NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\(")


# ---------------------------------------------------------------------------
# 接入：校验本地树、写 repo_meta（不 clone）
# ---------------------------------------------------------------------------


# DAG 节点 ingest：确认源码目录存在，采集 git 元数据，不列文件、不扫漏洞。
def run_ingest(ctx: ScanContext) -> None:
    source = Path(ctx.request.source).resolve()
    if not source.exists():
        raise FileNotFoundError(f"ingest: source not found: {source}")
    if not source.is_dir():
        raise NotADirectoryError(f"ingest: source is not a directory: {source}")

    git_info = inspect_git(source, ctx.request.since, ctx.request.until)
    meta = {
        "source": str(source),
        "exists": True,
        "since": ctx.request.since.isoformat() if ctx.request.since else None,
        "until": ctx.request.until.isoformat() if ctx.request.until else None,
        "branches": ctx.request.branches or ([git_info["branch"]] if git_info.get("branch") else []),
        "subsystems": ctx.request.subsystems,
        "git": git_info,
    }
    (ctx.work_dir / "repo_meta.json").write_text(
        json.dumps(meta, indent=2),
        encoding="utf-8",
    )
    changed = git_info.get("changed_files") or []
    if changed:
        (ctx.work_dir / "changed_files.json").write_text(
            json.dumps({"files": changed}, indent=2),
            encoding="utf-8",
        )


# 读本地 git 的 HEAD/分支/describe；有时间窗时再列出变更文件。没有 .git 则全空。
def inspect_git(root: Path, since: datetime | None, until: datetime | None) -> dict:
    empty = {
        "is_git": False,
        "head": None,
        "head_short": None,
        "branch": None,
        "describe": None,
        "commits": [],
        "changed_files": [],
    }
    if not (root / ".git").exists() and not _rev_parse(root):
        return empty

    head = _run_git(root, ["rev-parse", "HEAD"])
    branch = _run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    # 有 tag 则带标签，没有 tag 则退回短 SHA；这是本次扫描的检出，不是发行版矩阵。
    describe = _run_git(root, ["describe", "--tags", "--always"])
    commits: list[str] = []
    changed: list[str] = []
    if since or until:
        log_cmd = ["log", "--pretty=%H"]
        if since:
            log_cmd.append(f"--since={since.isoformat()}")
        if until:
            log_cmd.append(f"--until={until.isoformat()}")
        raw = _run_git(root, log_cmd)
        commits = [line for line in raw.splitlines() if line]
        if commits:
            diff = _run_git(root, ["diff", "--name-only", f"{commits[-1]}^..{commits[0]}"])
            changed = [line for line in diff.splitlines() if line]
    return {
        "is_git": True,
        "head": head or None,
        "head_short": (head or "")[:12] or None,
        "branch": branch or None,
        "describe": describe or None,
        "commits": commits,
        "changed_files": changed,
    }


# 判断 root 是否在 git 工作树内（子目录也能认）。
def _rev_parse(root: Path) -> bool:
    return bool(_run_git(root, ["rev-parse", "--is-inside-work-tree"]))


# 在 root 下执行 git；本机无 git 或命令失败时返回空串，不抛给流水线。
def _run_git(root: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# 索引：列源文件 + 子系统归属（规则在 knowledge/oh_modules.yml）
# ---------------------------------------------------------------------------


# DAG 节点 index：列出待扫源文件。全仓用路径前缀；拆开的组件仓用目录名回填子系统。
def run_index(ctx: ScanContext) -> None:
    root = Path(ctx.request.source).resolve()
    rules = load_rules()
    standalone = load_standalone().get(root.name.lower())
    requested = [name.lower() for name in ctx.request.subsystems]

    candidates = _changed_paths(ctx.work_dir, root)
    if candidates is None:
        rel_paths = list(_walk_source_files(root))
    else:
        rel_paths = [p for p in candidates if _is_source_file(root / p)]

    records: list[dict] = []
    for rel in rel_paths:
        subsystem = match_subsystem(rel, rules) or standalone
        if requested and (subsystem or "").lower() not in requested:
            continue
        records.append({"path": rel, "subsystem": subsystem})

    truncated = len(records) > MAX_FILES
    records = records[:MAX_FILES]
    counts = Counter(item["subsystem"] or "unmapped" for item in records)

    (ctx.work_dir / "file_index.json").write_text(
        json.dumps(
            {
                "source": str(root),
                "file_count": len(records),
                "truncated": truncated,
                "incremental": candidates is not None,
                "files": records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (ctx.work_dir / "module_map.json").write_text(
        json.dumps(
            {
                "subsystems_requested": ctx.request.subsystems,
                "counts": dict(counts),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


# 读取 paths 列表，长前缀在前，便于 foundation/communication 压过 communication。
def load_rules(yaml_path: Path | None = None) -> list[tuple[str, str]]:
    path = yaml_path or _YAML_PATH
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules: list[tuple[str, str]] = []
    for item in data.get("subsystems") or []:
        name = str(item.get("name") or "").strip()
        for prefix in item.get("paths") or []:
            norm = str(prefix).replace("\\", "/").strip("/")
            if name and norm:
                rules.append((norm, name))
    rules.sort(key=lambda pair: len(pair[0]), reverse=True)
    return rules


# 拆开的组件仓：根目录名 -> 子系统。全仓扫描对得上 paths 时不会用到。
def load_standalone(yaml_path: Path | None = None) -> dict[str, str]:
    path = yaml_path or _YAML_PATH
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mapping: dict[str, str] = {}
    for raw_name, raw_sub in (data.get("standalone") or {}).items():
        name = str(raw_name).strip().lower()
        sub = str(raw_sub).strip()
        if name and sub:
            mapping[name] = sub
    return mapping


# 按相对路径做最长前缀匹配；对不上返回 None（报告显示 n/a），不写 "unknown"。
def match_subsystem(rel_path: str, rules: list[tuple[str, str]]) -> str | None:
    path = rel_path.replace("\\", "/")
    for prefix, name in rules:
        if path == prefix or path.startswith(prefix + "/"):
            return name
    return None


# ingest 若写下 changed_files.json，则只索引这些相对路径；文件已删则跳过。
def _changed_paths(work_dir: Path, root: Path) -> list[str] | None:
    path = work_dir / "changed_files.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    files = data.get("files") or []
    result: list[str] = []
    for raw in files:
        rel = str(raw).replace("\\", "/")
        full = root / rel
        if full.is_file():
            result.append(rel)
    return result


# 遍历源码树，跳过 SKIP_DIRS，只收 CODE_SUFFIXES。
def _walk_source_files(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name.lower() not in SKIP_DIRS]
        for name in filenames:
            full = Path(dirpath) / name
            if full.suffix.lower() not in CODE_SUFFIXES:
                continue
            rel = full.relative_to(root).as_posix()
            found.append(rel)
    return found


# 时间窗增量里筛掉非源文件。
def _is_source_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in CODE_SUFFIXES


# ---------------------------------------------------------------------------
# 定位：从本地文件截取告警所在函数（不采用 Semgrep 的 requires login）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceSlice:
    snippet: str
    function: str | None
    start_line: int | None
    end_line: int | None


# 引擎占位字符串不能当赛题「源码内容」。
def snippet_is_unusable(text: str | None) -> bool:
    if text is None:
        return True
    stripped = text.strip().lower()
    return stripped in _BAD_SNIPPETS


# 把 [lo, hi) 行格式化成带行号的文本；命中行前加 '>'。
def _format_chunk(lines: list[str], lo: int, hi: int, hit_index: int) -> str:
    chunk: list[str] = []
    for i in range(lo, hi):
        mark = ">" if i == hit_index else " "
        chunk.append(f"{mark}{i + 1:5d}| {lines[i]}")
    return "\n".join(chunk)


# 去掉行内 // 和整行 # 注释，避免把注释里的括号当函数签名。
def _code_part(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//"):
        return ""
    if "//" in line:
        return line[: line.index("//")]
    return line


# 从一行取出函数名（Foo::Bar）；if/while 和 obj.method( 不当作定义。
def _func_name_from_line(line: str) -> str | None:
    code = _code_part(line).strip()
    if not code:
        return None
    if re.match(r"(if|else\s+if|while|for|switch|catch)\s*\(", code):
        return None
    chosen = None
    for found in _NAME_BEFORE_PAREN.finditer(code):
        ident_at = found.start(1)
        if ident_at > 0 and code[ident_at - 1] in ".*":
            continue
        name = found.group(1)
        short = name.split("::")[-1]
        if short in _CTRL:
            continue
        chosen = name
    return chosen


# 从签名行起往后找函数体的第一个 '{'，声明（以 ';' 结束）返回 None。
def _find_body_open(lines: list[str], sig_idx: int) -> tuple[int, int] | None:
    for i in range(sig_idx, min(len(lines), sig_idx + 6)):
        for j, ch in enumerate(lines[i]):
            if ch == "{":
                return i, j
            if ch == ";" and i == sig_idx:
                return None
    return None


# 从 open 的 '{' 配对到对应 '}'，超过 _MAX_FUNC_LINES 视为失败。
def _match_close_brace(lines: list[str], open_line: int, open_col: int) -> int | None:
    depth = 0
    limit = min(len(lines), open_line + _MAX_FUNC_LINES)
    for i in range(open_line, limit):
        start_col = open_col if i == open_line else 0
        for ch in lines[i][start_col:]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
    return None


# 从命中行往上找包围它的函数；失败返回 None，调用方改用邻域截取。
def _enclosing_function(lines: list[str], hit_index: int) -> tuple[int, int, str] | None:
    begin = max(0, hit_index - _SIG_LOOKBACK)
    for sig_idx in range(hit_index, begin - 1, -1):
        name = _func_name_from_line(lines[sig_idx])
        if not name:
            continue
        opened = _find_body_open(lines, sig_idx)
        if opened is None:
            continue
        open_line, open_col = opened
        close_line = _match_close_brace(lines, open_line, open_col)
        if close_line is None:
            continue
        if open_line <= hit_index <= close_line:
            return sig_idx, close_line + 1, name
    return None


# 读文件并截取：优先整函数，否则命中行上下 fallback 行。
def read_source_slice(
    source_root: Path,
    rel_path: str,
    start_line: int,
    context: int = _FALLBACK_CONTEXT,
) -> SourceSlice:
    path = source_root / rel_path.replace("\\", "/")
    empty = SourceSlice("", None, None, None)
    if not path.is_file() or start_line < 1:
        return empty
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return empty
    index = start_line - 1
    if index >= len(lines):
        return empty
    found = _enclosing_function(lines, index)
    if found is not None:
        lo, hi, name = found
        return SourceSlice(
            snippet=_format_chunk(lines, lo, hi, index),
            function=name,
            start_line=lo + 1,
            end_line=hi,
        )
    lo = max(0, index - context)
    hi = min(len(lines), index + context + 1)
    return SourceSlice(
        snippet=_format_chunk(lines, lo, hi, index),
        function=None,
        start_line=lo + 1,
        end_line=hi,
    )


# 只要本地文件能读，就用整函数/邻域截取，忽略引擎的 requires login。
def load_source_location(
    source_root: Path,
    rel_path: str,
    start_line: int,
    engine_snippet: str | None = None,
    context: int = _FALLBACK_CONTEXT,
) -> SourceSlice:
    local = read_source_slice(source_root, rel_path, start_line, context=context)
    if local.snippet:
        return local
    if not snippet_is_unusable(engine_snippet):
        return SourceSlice(engine_snippet or "", None, start_line, start_line)
    return SourceSlice("", None, None, None)


# 兼容旧调用：只返回格式化后的文本。
def read_source_snippet(
    source_root: Path,
    rel_path: str,
    start_line: int,
    context: int = _FALLBACK_CONTEXT,
) -> str:
    return read_source_slice(source_root, rel_path, start_line, context=context).snippet


# 引擎 snippet 不可用时从本地截；有本地文件时始终走本地。
def resolve_snippet(
    source_root: Path,
    rel_path: str,
    start_line: int,
    engine_snippet: str | None,
) -> str:
    return load_source_location(source_root, rel_path, start_line, engine_snippet).snippet


# ---------------------------------------------------------------------------
# 影响范围：把索引里的模块/子系统/分支填回 Finding（不做跨分支 checkout）
# ---------------------------------------------------------------------------


# DAG 节点 impact：子系统来自 file_index；没有 git 分支就留空，由报告渲染 n/a。
def run_impact(ctx: ScanContext) -> None:
    source = Path(ctx.request.source)
    index_map = _load_index_map(ctx.work_dir)
    repo_meta = _load_json(ctx.work_dir / "repo_meta.json")
    git = (repo_meta or {}).get("git") or {}
    default_branch = (
        (ctx.request.branches[0] if ctx.request.branches else None)
        or git.get("branch")
        or None
    )
    git_head = git.get("head")
    scanned = _scanned_revision(git)
    for finding in ctx.findings:
        rel = finding.locations[0].path.replace("\\", "/") if finding.locations else ""
        if not finding.subsystem:
            finding.subsystem = index_map.get(rel) or (
                ctx.request.subsystems[0] if ctx.request.subsystems else None
            )
        if not finding.module and rel:
            finding.module = _guess_module(rel)
        if not finding.affected_branches and default_branch:
            finding.affected_branches = [default_branch]
        finding.extra.setdefault("source_root", str(source))
        if git_head:
            finding.extra.setdefault("git_head", git_head)
        if scanned:
            finding.extra.setdefault("scanned_revision", scanned)
            # 指纹没给出版本时，只声明当前扫到的 revision，避免空字段被当成已做全版本验证。
            if not finding.affected_versions:
                finding.affected_versions = [scanned]
                finding.extra.setdefault("version_basis", "scanned_revision")


# 优先 git describe（tag 或短 SHA）；没有 describe 再用 HEAD 前 12 位。
def _scanned_revision(git: dict) -> str | None:
    describe = str(git.get("describe") or "").strip()
    if describe:
        return describe
    short = str(git.get("head_short") or git.get("head") or "").strip()
    return short[:12] if short else None


# 相对路径 -> 索引里记下的子系统（可能是 None）。
def _load_index_map(work_dir: Path) -> dict[str, str | None]:
    data = _load_json(work_dir / "file_index.json") or {}
    mapping: dict[str, str | None] = {}
    for item in data.get("files") or []:
        if isinstance(item, dict) and item.get("path"):
            mapping[str(item["path"]).replace("\\", "/")] = item.get("subsystem")
    return mapping


# 读 JSON 对象；文件不存在返回 None。
def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# 用路径第一段当模块名（frameworks/... -> frameworks）。
def _guess_module(path: str) -> str | None:
    parts = Path(path).parts
    return parts[0] if parts else None
