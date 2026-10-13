"""Semgrep 引擎：本地调用静态审计工具，产出原始告警。

不在这里做 CVE、PoC、是否安全漏洞的最终判定。
"""

from __future__ import annotations

import json
import os
import shutil
import site
import subprocess
from pathlib import Path

from ohscan.engines.base import Engine, run_engine
from ohscan.models.finding import (
    Confidence,
    Finding,
    Severity,
    SourceLocation,
)
from ohscan.locate import load_source_location
from ohscan.pipeline import ScanContext

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RULES_DIR = _REPO_ROOT / "knowledge" / "rules" / "semgrep"


class SemgrepEngine(Engine):
    name = "semgrep"

    # 读 file_index 顶层目录，跑 pysemgrep，把 JSON 命中转成 Finding。
    def scan(self, ctx: ScanContext) -> list[Finding]:
        source = Path(ctx.request.source).resolve()
        targets = _index_targets(ctx.work_dir, source)
        if not targets:
            return []
        if not _RULES_DIR.exists() or not _rule_files():
            raise FileNotFoundError(f"semgrep rules not found: {_RULES_DIR}")

        payload = _run_semgrep(source, targets, ctx.request.jobs, ctx.work_dir)
        index_meta = _load_index_map(ctx.work_dir)
        findings: list[Finding] = []
        for hit in payload.get("results") or []:
            finding = _to_finding(hit, source, index_meta)
            if finding:
                findings.append(finding)
        return findings


# DAG 节点 semgrep：适配器入口，结果写入 raw/semgrep.jsonl。
def run_semgrep(ctx: ScanContext) -> None:
    run_engine(SemgrepEngine(), ctx)


# 用索引里的顶层目录当扫描根（如 frameworks/），避免逐文件漏扫和 Windows 命令行过长。
def _index_targets(work_dir: Path, source: Path) -> list[Path]:
    index_file = work_dir / "file_index.json"
    if not index_file.exists():
        return [source]
    data = json.loads(index_file.read_text(encoding="utf-8"))
    tops: set[Path] = set()
    for item in data.get("files") or []:
        rel = item.get("path") if isinstance(item, dict) else item
        rel_text = str(rel).replace("\\", "/")
        top = rel_text.split("/")[0]
        path = source / top
        if path.exists():
            tops.add(path)
    return sorted(tops) if tops else [source]


# 相对路径 -> 子系统，方便 Finding.subsystem 先填上。
def _load_index_map(work_dir: Path) -> dict[str, str | None]:
    index_file = work_dir / "file_index.json"
    if not index_file.exists():
        return {}
    data = json.loads(index_file.read_text(encoding="utf-8"))
    mapping: dict[str, str | None] = {}
    for item in data.get("files") or []:
        if isinstance(item, dict) and item.get("path"):
            mapping[str(item["path"]).replace("\\", "/")] = item.get("subsystem")
    return mapping


# 列出 Scripts 里的 pysemgrep；Windows 上 pip 装的常不在 PATH。
def _resolve_semgrep() -> Path:
    for name in ("pysemgrep", "semgrep"):
        found = shutil.which(name)
        if found:
            return Path(found)
    script_dirs: list[Path] = []
    for packages in (site.getusersitepackages(), *site.getsitepackages()):
        script_dirs.append(Path(packages).resolve().parent / "Scripts")
    for folder in script_dirs:
        for name in ("pysemgrep.exe", "pysemgrep", "semgrep.exe", "semgrep"):
            candidate = folder / name
            if candidate.is_file():
                return candidate
    raise RuntimeError(
        "semgrep is installed but not on PATH; expected pysemgrep in Python Scripts"
    )


# 收集 knowledge/rules/semgrep 下全部规则文件。
def _rule_files() -> list[Path]:
    return sorted(_RULES_DIR.glob("*.yml")) + sorted(_RULES_DIR.glob("*.yaml"))


# ArkTS 的 .ets 不当 TypeScript 解析；第二次扫描只喂 JS/TS 规则，并强制语言。
def _typescript_rule_files() -> list[Path]:
    path = _RULES_DIR / "typescript-sinks.yml"
    return [path] if path.is_file() else []


# Windows CreateProcess 命令行上限约 32767 字符。appspawn 这种几百个文件
# 若把绝对路径全拼进 argv，会 WinError 206，被误当成「找不到 semgrep」。
_MAX_CMDLINE = 24000
# 单批超时后跳过这一批，避免整次 scan 卡死没有报告。
_BATCH_TIMEOUT = 900


# 相对路径分批调用 semgrep；某一批或 .ets 失败时跳过，保留其它命中。
def _run_semgrep(
    source: Path, targets: list[Path], jobs: int, work_dir: Path | None = None
) -> dict:
    executable = _resolve_semgrep()
    rel_targets = [_rel_target(source, path) for path in targets]
    merged: dict = {"results": []}
    skips: list[str] = []
    for batch in _target_batches(executable, rel_targets, jobs):
        payload = _invoke_semgrep_or_skip(
            executable, source, batch, jobs, skips, label="main"
        )
        merged["results"].extend(payload.get("results") or [])
    ets_files = _ets_rel_paths(source, targets, work_dir)
    ts_rules = _typescript_rule_files()
    extra = ["--lang", "typescript", "--scan-unknown-extensions"]
    if ets_files and ts_rules:
        for batch in _target_batches(
            executable, ets_files, jobs, rules=ts_rules, extra=extra, fallback=None
        ):
            payload = _invoke_semgrep_or_skip(
                executable,
                source,
                batch,
                jobs,
                skips,
                label="ets",
                rules=ts_rules,
                extra=extra,
            )
            merged["results"].extend(payload.get("results") or [])
    _write_skips(work_dir, skips)
    return merged


# 把跳过原因落到 raw/，方便对照「为什么少了一批」而不是静默丢结果。
def _write_skips(work_dir: Path | None, skips: list[str]) -> None:
    if not work_dir or not skips:
        return
    raw = work_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "semgrep_skip.txt").write_text("\n".join(skips) + "\n", encoding="utf-8")


# 单批超时/解析失败时记下并返回空，未安装或命令行过长仍抛出。
def _invoke_semgrep_or_skip(
    executable: Path,
    source: Path,
    targets: list[str],
    jobs: int,
    skips: list[str],
    label: str,
    rules: list[Path] | None = None,
    extra: list[str] | None = None,
) -> dict:
    try:
        return _invoke_semgrep(
            executable, source, targets, jobs, rules=rules, extra=extra
        )
    except RuntimeError as exc:
        text = str(exc)
        if "not installed" in text or "too long" in text:
            raise
        skips.append(f"{label} {targets}: {exc}")
        return {"results": []}


# 只列出要扫的 .ets；有索引用索引，否则在扫描根下找。
def _ets_rel_paths(
    source: Path, targets: list[Path], work_dir: Path | None
) -> list[str]:
    found: list[str] = []
    index_file = work_dir / "file_index.json" if work_dir else None
    if index_file and index_file.is_file():
        data = json.loads(index_file.read_text(encoding="utf-8"))
        for item in data.get("files") or []:
            rel = item.get("path") if isinstance(item, dict) else item
            rel_text = str(rel or "").replace("\\", "/")
            if rel_text.lower().endswith(".ets") and (source / rel_text).is_file():
                found.append(rel_text)
        return sorted(set(found))
    roots = targets or [source]
    for root in roots:
        base = root if root.is_dir() else root.parent
        if not base.exists():
            continue
        for path in base.rglob("*.ets"):
            if path.is_file():
                found.append(_rel_target(source, path))
    return sorted(set(found))


# 源码根下的相对路径，缩短 argv。
def _rel_target(source: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(source).as_posix()
    except ValueError:
        return str(path)


# 公共前缀：可执行文件 + 规则 + jobs；ets 二次扫描会带 --lang typescript。
def _base_cmd(
    executable: Path,
    jobs: int,
    rules: list[Path] | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    cmd = [
        str(executable),
        "scan",
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--jobs",
        str(max(1, jobs)),
    ]
    if extra:
        cmd.extend(extra)
    for rule in rules if rules is not None else _rule_files():
        cmd.extend(["--config", str(rule)])
    return cmd


# 估算命令行长度；Windows 用 list2cmdline。
def _cmdline_len(cmd: list[str]) -> int:
    if os.name == "nt":
        return len(subprocess.list2cmdline(cmd))
    return sum(len(part) + 1 for part in cmd)


# 按 Windows 命令行长度切批；主扫描单条目放不下时退回 "."，ets 扫描则拆成单文件。
def _target_batches(
    executable: Path,
    targets: list[str],
    jobs: int,
    rules: list[Path] | None = None,
    extra: list[str] | None = None,
    fallback: str | None = ".",
) -> list[list[str]]:
    prefix = _base_cmd(executable, jobs, rules=rules, extra=extra)
    batches: list[list[str]] = []
    current: list[str] = []
    for target in targets:
        candidate = current + [target]
        if current and _cmdline_len(prefix + candidate) > _MAX_CMDLINE:
            batches.append(current)
            current = [target]
        else:
            current = candidate
    if current:
        batches.append(current)
    if not batches:
        return [[fallback]] if fallback else []
    oversized = [batch for batch in batches if _cmdline_len(prefix + batch) > _MAX_CMDLINE]
    if not oversized:
        return batches
    if fallback:
        return [[fallback]]
    split: list[list[str]] = []
    for batch in batches:
        if _cmdline_len(prefix + batch) <= _MAX_CMDLINE:
            split.append(batch)
            continue
        for item in batch:
            if _cmdline_len(prefix + [item]) <= _MAX_CMDLINE:
                split.append([item])
    return split


# 真正调起 pysemgrep；exit 1 表示有 findings，仍算成功。超时或坏 JSON 抛 RuntimeError 给上层跳过。
def _invoke_semgrep(
    executable: Path,
    source: Path,
    targets: list[str],
    jobs: int,
    rules: list[Path] | None = None,
    extra: list[str] | None = None,
) -> dict:
    cmd = _base_cmd(executable, jobs, rules=rules, extra=extra) + targets
    env = os.environ.copy()
    env["PATH"] = str(executable.parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        proc = subprocess.run(
            cmd,
            cwd=source,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=_BATCH_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"semgrep timed out after {_BATCH_TIMEOUT}s") from exc
    except FileNotFoundError as exc:
        if getattr(exc, "winerror", None) == 206:
            raise RuntimeError(
                "semgrep command line is too long on Windows; retry with fewer files"
            ) from exc
        raise RuntimeError("semgrep is not installed; pip install semgrep") from exc
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout or "").strip() or "semgrep failed"
        raise RuntimeError(detail)
    if not proc.stdout.strip():
        return {"results": []}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep json: {exc}") from exc


# 把 Semgrep 一条 JSON 命中转成 Finding。CWE 来自规则；CVE 不在这里填。
def _to_finding(hit: dict, source: Path, index_meta: dict[str, str | None]) -> Finding | None:
    path = hit.get("path") or ""
    start = (hit.get("start") or {}).get("line") or 0
    extra = hit.get("extra") or {}
    metadata = extra.get("metadata") or {}
    check_id = _rule_id(hit.get("check_id") or "unknown")
    rel = _rel_path(source, path)
    cwe_id, cwe_name = _cwe_of(metadata)
    start_line = int(start)
    slice_ = load_source_location(source, rel, start_line, extra.get("lines"))
    return Finding(
        id=f"semgrep:{check_id}:{rel}:{start}",
        title=check_id,
        summary=extra.get("message") or check_id,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        severity=_severity_of(extra.get("severity")),
        confidence=_confidence_of(check_id, metadata),
        locations=[
            SourceLocation(
                path=rel,
                start_line=start_line,
                end_line=slice_.end_line,
                function=slice_.function,
                snippet=slice_.snippet or None,
            )
        ],
        sink=check_id,
        subsystem=index_meta.get(rel.replace("\\", "/")),
        engines=["semgrep"],
    )


def _rule_id(check_id: str) -> str:
    """Semgrep 在 --config 指向文件时会把规则路径编进 check_id，只保留 oh.* 规则名。"""
    marker = ".oh."
    if marker in check_id:
        return "oh." + check_id.split(marker, 1)[1]
    return check_id


# 相对路径；解析失败时保留原字符串。
def _rel_path(source: Path, raw: str) -> str:
    path = Path(raw)
    try:
        return path.resolve().relative_to(source).as_posix()
    except ValueError:
        return path.as_posix()


# 规则 metadata 里的 CWE 编号和名字。
def _cwe_of(metadata: dict) -> tuple[str | None, str | None]:
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    name = metadata.get("cwe_name")
    if cwe:
        return str(cwe), (str(name) if name else None)
    return None, None


# Semgrep ERROR -> high，WARNING -> medium。
def _severity_of(raw: object) -> Severity:
    text = str(raw or "").upper()
    if text == "ERROR":
        return Severity.HIGH
    if text == "WARNING":
        return Severity.MEDIUM
    return Severity.LOW


# 规则 metadata.confidence 优先；gets 即使没写也标 high；其余默认 medium。
def _confidence_of(check_id: str, metadata: dict) -> Confidence:
    raw = str(metadata.get("confidence") or "").strip().lower()
    if raw == "high":
        return Confidence.HIGH
    if raw == "low":
        return Confidence.LOW
    if raw == "medium":
        return Confidence.MEDIUM
    if check_id == "oh.gets":
        return Confidence.HIGH
    return Confidence.MEDIUM
