"""静态交付：修复占位建议 + report.json（模型入口）+ report.md（人读投影）。

JSON 空字段保持 null / []；Markdown 渲染时才写成「无」。
动态阶段只应读取 report/report.json，不要解析 Markdown。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ohscan.models.finding import Finding

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext

SCHEMA_VERSION = "1.0"
KIND = "ohsleuth.scan_report"

_VERDICT_ZH = {
    "confirm": "确认",
    "downgrade": "降级",
    "reject": "驳回",
}
_SURFACE_ZH = {
    "napi": "NAPI",
    "file-uri": "文件 URI",
    "internal": "内部调用",
    "unknown": "未知",
}
_POC_ZH = {
    "not_started": "未开始",
    "generated": "已生成",
    "verified": "已验证",
    "failed": "已失败",
    "skipped": "已跳过",
}
_SEV_ZH = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
}

# 按 sink 给具体改法。动态阶段会原样读进 report.json，不要写空话。
_FIX_BY_SINK = {
    "oh.path-find-prefix": (
        "目录边界必须落到分隔符上：比较 prefix + '/'，或先规范化再检查。"
        "「/data/storage/el1/base」没有尾斜杠时，也会匹配「/data/storage/el1/baseX」。"
    ),
    "oh.path-area-prefix": (
        "应比较 AREA 常量加尾斜杠（prefix + '/'），不要只用 find(AREA)==0。"
        "这些常量是「/data/storage/elN/base」，没有尾斜杠，否则会误匹配 baseX。"
        "若已调用 GetAppBaseDir，必须用返回的本应用 baseDir 做目录边界，不能只用全局 AREA。"
    ),
    "oh.strncmp-path-prefix": (
        "比较长度应包含后面的 '/'，或改用真正的路径规范化接口，"
        "不要只用 strncmp(path, prefix, strlen(prefix))。"
    ),
    "oh.fopen-concat": (
        "不要 fopen 拼接出来的用户路径。先规范化，再确认结果仍在沙箱目录内。"
    ),
    "oh.open-concat": (
        "不要 open() 拼接出来的用户路径。先规范化，再确认结果仍在沙箱目录内。"
    ),
    "oh.strcpy-unbounded": (
        "用带目标容量的拷贝替换 strcpy（memcpy/strncpy + 显式写入 NUL）。"
    ),
    "oh.strcat-unbounded": (
        "用剩余空间做有界追加，替换 strcat。"
    ),
    "oh.sprintf-unbounded": (
        "用 snprintf(dst, sizeof dst, ...) 替换 sprintf。"
    ),
    "oh.gets": (
        "用 fgets(buf, sizeof buf, stdin) 或等价接口替换 gets()。"
    ),
    "oh.memcpy-strlen": (
        "memcpy 长度用 min(strlen(src)+1, 目标容量)，不要只用 strlen(src)。"
    ),
    "oh.vsprintf-unbounded": (
        "用 vsnprintf(dst, sizeof dst, fmt, ap) 替换 vsprintf。"
    ),
    "oh.scanf-unbounded-s": (
        "给 %s 加宽度（例如 %255s），或读入动态缓冲区。"
    ),
    "oh.printf-format-string": (
        "格式串必须用字符串字面量；不可信缓冲区只作为 %s 参数。"
    ),
    "oh.system-command": (
        "不要把拼出来的字符串交给 system()；改用 execve 和 argv 数组。"
    ),
    "oh.popen-command": (
        "不要把拼出来的字符串交给 popen()；用固定命令或 execve。"
    ),
    "oh.stpcpy-unbounded": (
        "用带目标容量的拷贝替换 stpcpy，并显式写入终止符。"
    ),
    "oh.wcscpy-unbounded": (
        "用带目标容量的宽字符拷贝替换 wcscpy。"
    ),
    "oh.wcscat-unbounded": (
        "用剩余空间做有界宽字符追加，替换 wcscat。"
    ),
    "oh.getwd": (
        "用 getcwd(buf, sizeof buf) 替换 getwd()。"
    ),
    "oh.wsprintf-unbounded": (
        "用有界的 swprintf/snprintf 替换 wsprintf。"
    ),
    "oh.scanf-unbounded-ls": (
        "给宽扫描加宽度，或改用带长度的接口。"
    ),
    "oh.exec-command": (
        "不要把拼出来的路径交给 exec*；用固定路径和 argv 数组。"
    ),
    "oh.posix-spawn-command": (
        "posix_spawn 的文件路径必须是固定字面量或经过白名单校验。"
    ),
    "oh.openat-concat": (
        "不要 openat 拼接出来的用户路径。先规范化，再确认仍在沙箱内。"
    ),
    "oh.java-runtime-exec": (
        "不要把拼出来的字符串交给 Runtime.exec；改用 ProcessBuilder 的参数列表，或固定命令。"
    ),
    "oh.java-process-builder": (
        "ProcessBuilder 的命令必须是固定字面量或白名单；不要把用户字符串当整行 shell。"
    ),
    "oh.java-file-concat": (
        "不要 new File(目录 + 用户名)。先规范化，再确认仍在沙箱目录内。"
    ),
    "oh.ts-exec-command": (
        "不要把拼出来的字符串交给 exec/execSync；改用 execFile 和 argv 数组。"
    ),
    "oh.ts-fs-concat": (
        "不要把拼接路径交给 fs 读写。先规范化，再确认仍在允许目录内。"
    ),
    "oh.ets-fs-concat": (
        "不要把拼接路径交给 @ohos.file.fs。先规范化，再确认仍在沙箱目录内。"
    ),
}


# 旧扫描留下的英文套话；只替换已知模板，不改人工写的建议。
_LEGACY_FIX_ZH = {
    "Require a directory boundary: after AREA1/2/5 the next character must be '/' "
    "(compare against prefix + '/'). These constants are '/data/storage/elN/base' "
    "with no trailing slash.": _FIX_BY_SINK["oh.path-area-prefix"],
    "Require a trailing slash after the AREA prefix.": _FIX_BY_SINK["oh.path-find-prefix"],
}


# 把历史英文修复建议换成中文模板；未知句子原样返回。
def localize_fix_advice(text: str | None) -> str | None:
    if not text:
        return text
    return _LEGACY_FIX_ZH.get(text, text)


# DAG 节点 fix：按 sink 填可操作建议；已有中文建议不覆盖，已知英文套话会译成中文。
def run_fix(ctx: ScanContext) -> None:
    for finding in ctx.findings:
        if finding.fix_advice:
            finding.fix_advice = localize_fix_advice(finding.fix_advice)
            continue
        sink = finding.sink or finding.title or ""
        finding.fix_advice = _FIX_BY_SINK.get(
            sink,
            f"在 API 边界拒绝不可信输入，并在进入 {sink or '汇点'} 前做严格的长度/归属检查。",
        )


# Finding -> 普通 dict，供 report.json 和 API 共用。
def dump_finding(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


# jsonl 一行一条，后端 GET /findings 仍读这个文件。
def dump_finding_line(finding: Finding) -> str:
    return finding.model_dump_json()


# rejected 只留研判原因和位置，避免把整段 snippet 塞进模型上下文。
def compact_rejected(finding: Finding) -> dict[str, Any]:
    loc = finding.locations[0] if finding.locations else None
    return {
        "id": finding.id,
        "title": finding.title,
        "sink": finding.sink,
        "fp_reason": finding.fp_reason,
        "path": loc.path if loc else None,
        "start_line": loc.start_line if loc else None,
        "function": loc.function if loc else None,
    }


# 从 ctx 和 ingest/index 元数据拼出唯一交付文档；MD 不得另读 Finding。
def build_report_doc(ctx: ScanContext) -> dict[str, Any]:
    meta = _load_json(ctx.work_dir / "repo_meta.json") or {}
    git = meta.get("git") or {}
    index = _load_json(ctx.work_dir / "file_index.json") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "scan": {
            "source": ctx.request.source,
            "engines": list(ctx.request.engines),
            "since": meta.get("since"),
            "until": meta.get("until"),
            "git_branch": git.get("branch") or None,
            "git_head": git.get("head") or None,
            "indexed_files": index.get("file_count", 0),
            "incremental": bool(index.get("incremental", False)),
            "accepted": len(ctx.findings),
            "rejected": len(ctx.rejected),
        },
        "findings": [dump_finding(item) for item in ctx.findings],
        "rejected": [compact_rejected(item) for item in ctx.rejected],
    }


# Markdown 专用：JSON 里的空值到人读报告才变成「无」。
def md_text(value: object, empty: str = "无") -> str:
    if value is None or value == "" or value == []:
        return empty
    if isinstance(value, list):
        return "、".join(str(item) for item in value) if value else empty
    return str(value)


# 枚举值只在 Markdown/UI 翻译；JSON 里仍是英文。
def _zh(table: dict[str, str], raw: object) -> str:
    key = str(raw or "").strip()
    if not key:
        return "无"
    return table.get(key, key)


# 只消费 build_report_doc 的字典，保证 CWE/CVE/位置与 JSON 不漂移。
def render_markdown(doc: dict[str, Any]) -> str:
    scan = doc["scan"]
    lines = [
        "# OHSleuth 漏洞分析报告",
        "",
        f"- 源码：`{scan.get('source')}`",
        f"- 引擎：{md_text(scan.get('engines'))}",
        f"- 时间窗：{md_text(scan.get('since'))} .. {md_text(scan.get('until'))}",
        f"- Git 分支：{md_text(scan.get('git_branch'))}",
        f"- Git HEAD：{md_text(scan.get('git_head'))}",
        f"- 索引文件数：{scan.get('indexed_files', 0)}",
        f"- 增量扫描：{'是' if scan.get('incremental') else '否'}",
        f"- 已接受告警：{scan.get('accepted', 0)}",
        f"- 研判剔除：{scan.get('rejected', 0)}",
        "",
    ]
    findings = doc.get("findings") or []
    if not findings:
        lines.append("本次没有已接受的漏洞告警。")
        lines.append("")
        rejected_n = scan.get("rejected") or 0
        if rejected_n:
            lines.append(f"有 {rejected_n} 条原始命中被研判剔除，详见 rejected.jsonl。")
        else:
            lines.append("0 条告警表示规则未命中，不等于扫描失败。")
        lines.append("")
        return "\n".join(lines)
    for finding in findings:
        loc = (finding.get("locations") or [{}])[0]
        cwe = f"{md_text(finding.get('cwe_id'))} {finding.get('cwe_name') or ''}".rstrip()
        lines.extend(
            [
                f"## {finding.get('id')} {finding.get('title')}",
                "",
                finding.get("summary") or "_暂无描述。_",
                "",
                f"- CWE：{cwe}",
                f"- CVE：{md_text(finding.get('cve_ids'))}",
                f"- 严重程度：{_zh(_SEV_ZH, finding.get('severity'))}",
                f"- 模块：{md_text(finding.get('module'))}",
                f"- 子系统：{md_text(finding.get('subsystem'))}",
                f"- 分支：{md_text(finding.get('affected_branches'))}",
                f"- PoC：{_zh(_POC_ZH, finding.get('poc_status'))}",
                f"- PoC 命令：{md_text(finding.get('poc_cmd'))}",
                f"- PoC 路径：{md_text(finding.get('poc_path'))}",
                "",
            ]
        )
        evidence = finding.get("evidence")
        if evidence or finding.get("poc_cmd"):
            lines.extend(
                [
                    "### PoC（本地 CWE 演示，非设备利用）",
                    "",
                    f"- 状态：{_zh(_POC_ZH, finding.get('poc_status'))}",
                    f"- 命令：{md_text(finding.get('poc_cmd'))}",
                    f"- 路径：{md_text(finding.get('poc_path'))}",
                    "",
                ]
            )
            if evidence:
                lines.extend(["```", str(evidence).strip(), "```", ""])
            poc_chain = (finding.get("extra") or {}).get("poc") or {}
            steps = poc_chain.get("steps") or []
            if steps:
                lines.extend(["证据链：", ""])
                for step in steps:
                    title = str((step or {}).get("title") or "").strip()
                    detail = str((step or {}).get("detail") or "").strip()
                    if title:
                        lines.append(f"- {title}：{detail}" if detail else f"- {title}")
                lines.append("")
        lines.extend(
            [
                "### 修复建议",
                "",
                localize_fix_advice(finding.get("fix_advice")) or "_待补充。_",
                "",
            ]
        )
        extra_dyn = (finding.get("extra") or {}).get("dynamic") or {}
        if extra_dyn:
            lines.extend(["### 动态研判", ""])
            if extra_dyn.get("error"):
                lines.append(f"- 动态阶段错误：{extra_dyn.get('error')}")
                lines.append("")
            else:
                surface = finding.get("attack_surface") or extra_dyn.get("attack_surface")
                lines.extend(
                    [
                        f"- 裁决：{_zh(_VERDICT_ZH, extra_dyn.get('verdict'))}",
                        f"- 攻击面：{_zh(_SURFACE_ZH, surface)}",
                        f"- 触发：{md_text(extra_dyn.get('trigger'))}",
                        f"- 代码复现链：{md_text(extra_dyn.get('reproduction'))}",
                        f"- 影响：{md_text(extra_dyn.get('impact'))}",
                        f"- 为何非误报：{md_text(extra_dyn.get('why_not_fp'))}",
                        f"- 理由：{md_text(extra_dyn.get('rationale'))}",
                        f"- 证据缺口：{md_text(extra_dyn.get('evidence_gap'))}",
                        "",
                    ]
                )
                cot = extra_dyn.get("cot") or []
                if cot:
                    lines.append("研判步骤：")
                    lines.append("")
                    for i, step in enumerate(cot, start=1):
                        lines.append(f"{i}. {step}")
                    lines.append("")
        if loc.get("path"):
            loc_line = f"`{loc.get('path')}:{loc.get('start_line')}`"
            if loc.get("function"):
                loc_line += f" `{loc.get('function')}`"
            lines.extend(["### 源码位置", "", loc_line, ""])
            if loc.get("snippet"):
                lines.extend(["```", loc["snippet"], "```", ""])
    return "\n".join(lines)


# DAG 节点 report：先落 JSON 契约，再投影 md 和 findings.jsonl。
def run_report(ctx: ScanContext) -> None:
    doc = build_report_doc(ctx)
    report_dir = ctx.report_dir
    (report_dir / "report.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (report_dir / "report.md").write_text(render_markdown(doc), encoding="utf-8")
    with (ctx.work_dir / "findings.jsonl").open("w", encoding="utf-8") as handle:
        for finding in ctx.findings:
            handle.write(dump_finding_line(finding) + "\n")


# 读 JSON 对象；文件不存在返回 None。
def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
