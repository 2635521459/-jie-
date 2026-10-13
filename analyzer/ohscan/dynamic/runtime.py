"""动态运行时：读 report.json，固定思维链，按需调 tools，写回 extra.dynamic。

不改 cve_ids，不把 poc 标成 verified。引擎/triage 不得 import；DAG 通过 stage.py 在 report 之后调用。
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ohscan.deliver import render_markdown
from ohscan.dynamic.config import DynamicConfig, config_ready, load_config
from ohscan.dynamic.prefetch import ToolCache, prefetch_dossier
from ohscan.dynamic.tools import dispatch, tool_specs

ChatFn = Callable[[list[dict], list[dict]], dict]

_VERDICTS = {"confirm", "downgrade", "reject"}

_SYSTEM = """你是 OpenHarmony 静态告警的第二裁判，不是第一检测器。
不要发现新漏洞。不要编造 CVE。不要在设备或模拟器上执行利用。不要把 poc_status 写成 verified。

用户消息里的 dossier 已由本地工具预取（整函数、调用点、文件头常量、PoC 证据链）。
先根据 dossier 裁决。只有缺关键事实时才再调用 read_function / read_file / find_callers。
「复现」是用这些片段重建 谁调用 → 什么输入 → 到达汇点 → 缺了什么检查，
不是编译运行、不是打真实路径、不是写 exploit。

按 CWE 选择问题，不要默认当成沙箱路径问题：
-（每条都问）：输入是否来自应用/IPC/NAPI？汇点前有没有长度、归属、转义检查？是不是测试代码或死代码？
- CWE-22：才问目录边界、尾斜杠、baseDir 是否参与比较、是不是 file:// 分流。
- CWE-78：命令字符串谁拼接、是否有 argv 化、是否仅内部固定命令。
- CWE-120/242：目标缓冲区容量从哪来、拷贝长度是否受输入控制、有没有终止符。
- CWE-134：格式串是否来自外部、是否被当成字面量。
- CWE-190：乘法是否直接用作分配大小，分配前有没有对两个因子做上限检查。
- CWE-200：日志是否打印了密钥内容，而不是只打印长度或个数。
- CWE-415：两次释放是否在相邻两行；中间有没有语句、if/else 或赋空。

裁决：confirm（外部可触发且缺检查）| downgrade（链不全或仅内部）| reject（误报：测试/分流/死代码）。
dossier 不够就填 evidence_gap，并考虑 downgrade，不要猜。
最后只输出一个 JSON（键名英文，不要 markdown 代码块）：
{
  "verdict": "confirm",
  "summary": "两到四句中文：谁能触发、缺了什么检查、会造成什么后果",
  "trigger": "调用链 + 可控字段/缓冲区，必须能对上工具读到的符号",
  "reproduction": "用工具拼出的代码复现链（函数名与文件），并写明未在设备执行",
  "impact": "安全后果，不要只写 high",
  "why_not_fp": "为什么不是测试代码或该 CWE 的典型误报",
  "attack_surface": "napi|file-uri|internal|unknown",
  "evidence_gap": "工具没读到的关键事实；没有则空字符串",
  "rationale": "结合 CWE 与工具证据的短理由",
  "cot": ["补齐片段", "重建调用链", "对照该 CWE 的检查", "裁决"]
}
看完卷宗后必须给出 JSON，不要只调工具不收尾。
"""

# 工具轮次用尽后追加这一句，并去掉 tools，逼模型收尾。
_FINAL_ASK = (
    "不要再调用工具。根据 dossier 和已读到的整函数、调用点和常量，只输出上面要求的 JSON。"
    "reproduction 必须写代码链；未执行利用。缺证据就填 evidence_gap。"
)


# CLI / 测试入口。没配模型则跳过；chat_fn 注入时不走网络。
def run_dynamic(
    report_json: Path,
    config: DynamicConfig | None = None,
    chat_fn: ChatFn | None = None,
) -> dict:
    cfg = config or load_config()
    if not report_json.is_file():
        raise FileNotFoundError(f"missing report json: {report_json}")
    doc = json.loads(report_json.read_text(encoding="utf-8"))
    if doc.get("kind") != "ohsleuth.scan_report":
        raise ValueError("not an ohsleuth.scan_report")
    if chat_fn is None and not config_ready(cfg):
        return {
            "status": "skipped",
            "reason": "dynamic disabled or model not configured",
            "reviewed": 0,
        }

    source_root = Path(str((doc.get("scan") or {}).get("source") or ""))
    if not source_root.is_dir():
        raise FileNotFoundError(f"scan.source is not a directory: {source_root}")
    client = chat_fn or _openai_chat(cfg)
    # 同一次扫描共用缓存，避免 6 条 AREA 把整仓 walk 六遍。
    cache = ToolCache()
    reviewed = 0
    for finding in doc.get("findings") or []:
        _review_one(finding, source_root, client, cfg.max_tool_rounds, cache)
        reviewed += 1
    low_reviewed = _review_low_confidence(
        report_json, source_root, client, cfg.max_tool_rounds, cache
    )
    # 默认不改正式名单；只有配置显式打开才按 reject 挪到 rejected。
    if cfg.apply_verdict_to_accepted:
        _apply_verdicts_to_lists(doc)
    _write_back(report_json, doc)
    return {"status": "ok", "reviewed": reviewed, "low_reviewed": low_reviewed}


# 低置信度告警只补 extra.dynamic，不放进正式 findings。
def _review_low_confidence(
    report_json: Path,
    source_root: Path,
    chat_fn: ChatFn,
    max_rounds: int,
    cache: ToolCache,
) -> int:
    jsonl = report_json.parent.parent / "rejected.jsonl"
    if not jsonl.is_file():
        return 0
    rows = []
    reviewed = 0
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("fp_reason") == "below confidence threshold":
            _review_one(item, source_root, chat_fn, max_rounds, cache)
            reviewed += 1
        rows.append(item)
    jsonl.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return reviewed


# 仅当配置显式打开：把 dynamic.reject 从 findings 挪到 rejected。默认不改正式名单。
def _apply_verdicts_to_lists(doc: dict) -> None:
    kept = []
    extra_rejected = list(doc.get("rejected") or [])
    for finding in doc.get("findings") or []:
        verdict = str(((finding.get("extra") or {}).get("dynamic") or {}).get("verdict") or "")
        if verdict == "reject":
            loc = (finding.get("locations") or [{}])[0]
            extra_rejected.append(
                {
                    "id": finding.get("id"),
                    "title": finding.get("title"),
                    "sink": finding.get("sink"),
                    "fp_reason": "dynamic review reject",
                    "path": loc.get("path"),
                    "start_line": loc.get("start_line"),
                    "function": loc.get("function"),
                }
            )
            continue
        kept.append(finding)
    doc["findings"] = kept
    doc["rejected"] = extra_rejected
    scan = doc.setdefault("scan", {})
    scan["accepted"] = len(kept)
    scan["rejected"] = len(extra_rejected)


# 对一条 finding：先本地预取卷宗，再让模型裁决；缺事实才允许再调工具。
def _review_one(
    finding: dict,
    source_root: Path,
    chat_fn: ChatFn,
    max_rounds: int,
    cache: ToolCache,
) -> None:
    dossier, tools_used = prefetch_dossier(source_root, finding, cache)
    messages = [
        {"role": "system", "content": _SYSTEM},
        {
            "role": "user",
            "content": json.dumps(_finding_payload(finding, dossier), ensure_ascii=False),
        },
    ]
    payload: dict[str, Any] | None = None
    try:
        for _ in range(max(1, max_rounds)):
            reply = chat_fn(messages, tool_specs())
            calls = reply.get("tool_calls") or []
            if calls:
                _append_tool_results(
                    messages, source_root, calls, tools_used, reply.get("message")
                )
                continue
            payload = _parse_review(reply.get("content") or "")
            break
        # 只调工具不给 JSON 时，再要一轮且不带 tools；若仍返回 tool_calls 就执行后再问一次。
        if payload is None:
            payload, raw = _force_json(messages, source_root, chat_fn, tools_used)
            if payload is None:
                finding.setdefault("extra", {})["dynamic"] = {
                    "error": "model did not return review JSON",
                    "verdict": "downgrade",
                    "tools_used": tools_used,
                    "raw": raw[:1500],
                }
                return
    except Exception as exc:
        finding.setdefault("extra", {})["dynamic"] = {
            "error": str(exc),
            "verdict": "downgrade",
            "tools_used": tools_used,
        }
        return
    _apply_review(finding, payload, tools_used)


# 不带 tools 再问；若模型仍发 tool_calls，执行后再问一次。
def _force_json(
    messages: list[dict],
    source_root: Path,
    chat_fn: ChatFn,
    tools_used: list[str],
) -> tuple[dict[str, Any] | None, str]:
    last_raw = ""
    for _ in range(2):
        messages.append({"role": "user", "content": _FINAL_ASK})
        reply = chat_fn(messages, [])
        last_raw = reply.get("content") or ""
        calls = reply.get("tool_calls") or []
        if calls:
            _append_tool_results(
                messages, source_root, calls, tools_used, reply.get("message")
            )
        payload = _parse_review(last_raw)
        if payload is not None:
            return payload, last_raw
        if not calls:
            break
    return None, last_raw


# 执行本轮 tool_calls，把本地读盘结果追加进对话。
def _append_tool_results(
    messages: list[dict],
    source_root: Path,
    calls: list[dict],
    tools_used: list[str],
    assistant_message: dict | None = None,
) -> None:
    messages.append(
        assistant_message
        or {"role": "assistant", "content": None, "tool_calls": calls}
    )
    for call in calls:
        name = str(call.get("name") or "")
        args = call.get("arguments") or {}
        if isinstance(args, str):
            args = json.loads(args or "{}")
        tools_used.append(name)
        result = dispatch(source_root, name, args if isinstance(args, dict) else {})
        messages.append(
            {
                "role": "tool",
                "tool_call_id": str(call.get("id") or name),
                "name": name,
                "content": json.dumps(result, ensure_ascii=False),
            }
        )


# 卷宗 + 告警字段一起送给模型；PoC 步骤标明不是设备利用。
def _finding_payload(finding: dict, dossier: dict) -> dict:
    loc = (finding.get("locations") or [{}])[0]
    return {
        "instruction": (
            "dossier 已由本地工具预取。足够则直接输出 JSON；"
            "缺调用链或常量定义时再调工具。不要只根据原始 snippet 结案。"
            "PoC steps 是本机 CWE 演示，不是设备利用。"
        ),
        "id": finding.get("id"),
        "cwe_id": finding.get("cwe_id"),
        "cwe_name": finding.get("cwe_name"),
        "sink": finding.get("sink") or finding.get("title"),
        "summary": finding.get("summary"),
        "fix_advice": finding.get("fix_advice"),
        "module": finding.get("module"),
        "subsystem": finding.get("subsystem"),
        "path": loc.get("path"),
        "start_line": loc.get("start_line"),
        "function": loc.get("function"),
        "snippet": loc.get("snippet"),
        "dossier": dossier,
    }


# 从模型文本里抠出 JSON；允许 markdown 代码块或前后说明。
def _parse_review(text: str) -> dict[str, Any] | None:
    raw = text.strip()
    if not raw:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
    if fence:
        raw = fence.group(1).strip()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


# 把模型结论写回 finding；丢掉 CVE / verified 等越权字段。
def _apply_review(finding: dict, payload: dict, tools_used: list[str]) -> None:
    verdict = str(payload.get("verdict") or "").strip().lower()
    gap = str(payload.get("evidence_gap") or "")[:1000]
    if verdict not in _VERDICTS:
        # 模型胡写时不得抬成确认，避免假阳性进正式结论。
        verdict = "downgrade"
        if not gap:
            gap = "model returned invalid verdict"
    extra = finding.setdefault("extra", {})
    extra["dynamic"] = {
        "verdict": verdict,
        "rationale": str(payload.get("rationale") or "")[:2000],
        "trigger": str(payload.get("trigger") or "")[:2000],
        "reproduction": str(payload.get("reproduction") or "")[:2000],
        "impact": str(payload.get("impact") or "")[:2000],
        "why_not_fp": str(payload.get("why_not_fp") or "")[:2000],
        "evidence_gap": gap,
        "cot": [str(item) for item in (payload.get("cot") or [])][:8],
        "tools_used": tools_used,
    }
    summary = str(payload.get("summary") or "").strip()
    if summary:
        finding["summary"] = summary[:2000]
    surface = str(payload.get("attack_surface") or "").strip()
    if surface:
        finding["attack_surface"] = surface[:200]
    payload.pop("cve_ids", None)
    payload.pop("cve_id", None)
    payload.pop("poc_status", None)


# 与静态交付同源：改 JSON 后重写 md 和 findings.jsonl。
def _write_back(report_json: Path, doc: dict) -> None:
    report_json.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (report_json.parent / "report.md").write_text(render_markdown(doc), encoding="utf-8")
    jsonl = report_json.parent.parent / "findings.jsonl"
    with jsonl.open("w", encoding="utf-8") as handle:
        for finding in doc.get("findings") or []:
            handle.write(json.dumps(finding, ensure_ascii=False) + "\n")


# OpenAI 兼容 Chat Completions；未配置时不会被 run_dynamic 调用。
def _openai_chat(cfg: DynamicConfig) -> ChatFn:
    # 发一次 Chat Completions；tool_calls 原样交回循环，避免在此执行工具。
    def _call(messages: list[dict], tools: list[dict]) -> dict:
        import urllib.error
        import urllib.request

        url = cfg.base_url.rstrip("/") + "/chat/completions"
        body = {
            "model": cfg.model,
            "messages": _compat_messages(messages),
            "temperature": 0,
        }
        if tools:
            body["tools"] = tools
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cfg.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=cfg.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"dynamic model request failed: {exc}") from exc
        choice = ((data.get("choices") or [{}])[0].get("message") or {})
        tool_calls = []
        for item in choice.get("tool_calls") or []:
            fn = item.get("function") or {}
            tool_calls.append(
                {
                    "id": item.get("id"),
                    "name": fn.get("name"),
                    "arguments": fn.get("arguments") or "{}",
                }
            )
        return {
            "content": choice.get("content") or "",
            "tool_calls": tool_calls,
            "message": choice,
        }

    return _call


# 把内部 message 转成 Chat Completions 需要的 role 结构。
def _compat_messages(messages: list[dict]) -> list[dict]:
    out = []
    for item in messages:
        role = item.get("role")
        if role == "tool":
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": item.get("tool_call_id"),
                    "content": item.get("content") or "",
                }
            )
            continue
        out.append(item)
    return out
