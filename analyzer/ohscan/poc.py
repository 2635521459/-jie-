"""PoC 阶段：按 sink 写可编译的本地复现，不调模型，不访问设备。

Python 演示在扫描时执行。同目录的 .c 在有 gcc/clang 时用 -O0 -std=c11 编译并运行，
退出码 0 表示缺陷行为已在本进程触发（前缀误接受、路径逃出、canary 被改写、格式串被解释）。
命令类只证明元字符留在 shell 字符串里，不调用 system。
poc_status 只能是 generated / skipped / failed，禁止 verified。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ohscan.locate import SourceSlice, read_source_slice, snippet_is_unusable
from ohscan.models.finding import Finding, PocStatus, SourceLocation

if TYPE_CHECKING:
    from ohscan.pipeline import ScanContext

# 模板在仓库 knowledge/poc/，与 fingerprints.json 一样不打进 Python 包内部。
_REPO_ROOT = Path(__file__).resolve().parents[2]
_POC_DIR = _REPO_ROOT / "knowledge" / "poc"

# 抽不到 AREA 字面量时才用这条；与 request 样本常量一致。
_DEFAULT_PREFIX = "/data/storage/el1/base"
# 命令注入演示用的用户片段：证明会进 shell 字符串，扫描器不得执行它。
_DEFAULT_USER = "ok; id"
_RUN_TIMEOUT_SEC = 8

# 无尾斜杠的 find/strncmp 前缀检查。
_PREFIX_SINKS = {
    "oh.path-area-prefix",
    "oh.path-find-prefix",
    "oh.strncmp-path-prefix",
}
# 目录与用户名拼接后打开文件。
_CONCAT_SINKS = {
    "oh.fopen-concat",
    "oh.open-concat",
    "oh.openat-concat",
    "oh.java-file-concat",
    "oh.ts-fs-concat",
    "oh.ets-fs-concat",
}
# 非字面量命令进 system/popen/exec/Runtime.exec。
_CMD_SINKS = {
    "oh.system-command",
    "oh.popen-command",
    "oh.exec-command",
    "oh.posix-spawn-command",
    "oh.java-runtime-exec",
    "oh.java-process-builder",
    "oh.ts-exec-command",
}
# 无界拷贝 / 危险 gets。
_COPY_SINKS = {
    "oh.strcpy-unbounded",
    "oh.strcat-unbounded",
    "oh.sprintf-unbounded",
    "oh.gets",
    "oh.memcpy-strlen",
    "oh.vsprintf-unbounded",
    "oh.scanf-unbounded-s",
    "oh.stpcpy-unbounded",
    "oh.wcscpy-unbounded",
    "oh.wcscat-unbounded",
    "oh.getwd",
    "oh.wsprintf-unbounded",
    "oh.scanf-unbounded-ls",
}
# 非字面量格式串。
_FORMAT_SINKS = {"oh.printf-format-string"}

# 从源码里认 AREA1/2/5 或 PREFIX 的赋值、宏。
_AREA_TOKEN = re.compile(r"\b(AREA[125]|PREFIX)\b")
_AREA_DEFINE = re.compile(
    r'^\s*#define\s+(AREA[125]|PREFIX)\s+"([^"]+)"',
    re.MULTILINE,
)
_AREA_ASSIGN = re.compile(
    r'\b(AREA[125]|PREFIX)\s*=\s*"([^"]+)"',
)
# request 沙箱基路径；不要把 file:// 当成目录前缀。
_OH_BASE = re.compile(r'"(/data/storage/el[125]/base)"')
_QUOTED_DIR = re.compile(r'"((?:/|[A-Za-z]:\\)[^"]{2,120})"')


# 把 finding id 收成目录名，避免路径分隔符污染 poc 目录。
def _safe_dir_name(finding_id: str) -> str:
    chars = []
    for ch in finding_id:
        chars.append(ch if ch.isalnum() or ch in "._-" else "_")
    name = "".join(chars).strip("._") or "finding"
    return name[:160]


# JSON 字面量可直接嵌入生成的 .py，避免 PREFIX 里的引号把脚本弄坏。
def _py_lit(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


# C 字符串字面量。路径里的引号和反斜杠要转义。
def _c_lit(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# 与 _try_compile_c 的输出文件名一致，写进人读说明。
def _compile_hint(c_name: str) -> str:
    exe = Path(c_name).with_suffix(".exe").name if os.name == "nt" else "c_demo"
    if shutil.which("gcc") or shutil.which("clang") or shutil.which("cc"):
        return f"gcc -O0 -std=c11 {c_name} -o {exe} && {exe}"
    if _find_vcvars() is not None:
        return f"cl /nologo /Od /std:c11 {c_name} /Fe:{exe} && {exe}"
    return f"gcc -O0 -std=c11 {c_name} -o {exe} && {exe}"


# 读 knowledge/poc 下的模板；缺文件时返回空串，调用方改走仅截段。
def _load_template(name: str) -> str:
    path = _POC_DIR / name
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


# 只替换 <<NAME>>，不用 str.format，避免模板里的花括号被当成槽位。
def _fill(template: str, mapping: dict[str, str]) -> str:
    text = template
    for key, value in mapping.items():
        text = text.replace(f"<<{key}>>", value)
    return text


# 优先从本地源码重读函数，避免沿用引擎给的占位 snippet。
def _snippet_for(ctx: ScanContext, rel_path: str, start_line: int, existing: str | None) -> SourceSlice:
    local = read_source_slice(Path(ctx.request.source), rel_path, start_line)
    if local.snippet:
        return local
    if not snippet_is_unusable(existing):
        return SourceSlice(existing or "", None, start_line, start_line)
    return SourceSlice("", None, None, None)


# 读告警文件全文，供抽取 AREA 常量；读失败返回空串。
def _read_source_file(source_root: Path, rel_path: str) -> str:
    path = source_root / rel_path.replace("\\", "/")
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# 收集 AREA1= / #define AREA1 形式的字面量。
def _area_defs(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in _AREA_DEFINE.finditer(text):
        found[match.group(1)] = match.group(2)
    for match in _AREA_ASSIGN.finditer(text):
        found.setdefault(match.group(1), match.group(2))
    return found


# 从 snippet 优先、再全文：命中 AREA2 就用 AREA2 的值，不要一律 el1。
def extract_path_prefix(snippet: str, source_text: str) -> tuple[str, str]:
    blob = f"{snippet}\n{source_text}"
    defs = _area_defs(blob)
    for token in _AREA_TOKEN.findall(snippet):
        if token in defs:
            return defs[token], "snippet-token"
    for token in _AREA_TOKEN.findall(source_text):
        if token in defs:
            return defs[token], "file-token"
    match = _OH_BASE.search(snippet) or _OH_BASE.search(source_text)
    if match:
        return match.group(1), "literal"
    if defs:
        return next(iter(defs.values())), "define"
    return _DEFAULT_PREFIX, "default"


# 拼接类告警：尽量用源码里的目录字面量当 sandbox base。
def extract_concat_base(snippet: str, source_text: str) -> tuple[str, str]:
    prefix, origin = extract_path_prefix(snippet, source_text)
    if origin != "default":
        return prefix, origin
    match = _QUOTED_DIR.search(snippet) or _QUOTED_DIR.search(source_text)
    if match:
        return match.group(1), "quoted-dir"
    return _DEFAULT_PREFIX, "default"


# 扫描时只跑 Python 演示；失败不改研判，只把状态标 failed。
# 必须用绝对路径：--out 若是相对路径，cwd 切到 poc 目录后再传相对路径会拼成双份。
def _run_python(demo: Path) -> tuple[bool, str]:
    demo = demo.resolve()
    try:
        proc = subprocess.run(
            [sys.executable, str(demo)],
            cwd=str(demo.parent),
            check=False,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out[-4000:]


# 本机有 gcc/clang/cc 或 Visual Studio cl 才编译独立 .c；都没有则不算扫描失败。
def _try_compile_c(src: Path) -> tuple[bool, str]:
    src = src.resolve()
    compiler = next((name for name in ("gcc", "clang", "cc") if shutil.which(name)), None)
    # Windows 用 .exe；POSIX 用固定名，避免 with_suffix 把 .c 变成无扩展名后不好辨认。
    exe = src.with_suffix(".exe") if os.name == "nt" else src.parent / "c_demo"
    if compiler:
        argv = [compiler, "-O0", "-std=c11", str(src), "-o", str(exe)]
        built = _run_compile(argv, cwd=None)
    else:
        vcvars = _find_vcvars()
        if vcvars is None:
            return False, "no C compiler"
        # /Od 关闭优化，避免编译器把结构体内的越界写优化掉。
        cl_cmd = (
            f'call "{vcvars}" >nul && cl /nologo /Od /std:c11 '
            f'/Fe:"{exe}" "{src}"'
        )
        built = _run_compile(["cmd", "/c", cl_cmd], cwd=src.parent)
    if built is None:
        return False, "compile failed"
    if built.returncode != 0:
        return False, (built.stderr or built.stdout or "compile failed")[-2000:]
    try:
        ran = subprocess.run(
            [str(exe)],
            cwd=str(src.parent),
            check=False,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    out = ((ran.stdout or "") + (ran.stderr or "")).strip()
    return ran.returncode == 0, out[-4000:]


# vcvars 每次都要几秒；找到后缓存路径。
_VCVARS: str | None = None
_VCVARS_LOOKED = False


def _find_vcvars() -> str | None:
    global _VCVARS, _VCVARS_LOOKED
    if _VCVARS_LOOKED:
        return _VCVARS
    _VCVARS_LOOKED = True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return None
    try:
        proc = subprocess.run(
            [
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    install = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not install:
        return None
    bat = Path(install[-1].strip()) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    if not bat.is_file():
        return None
    _VCVARS = str(bat)
    return _VCVARS


def _run_compile(argv: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


# 人读复现说明：输入、错误行为、正确做法、如何运行。标明未在设备执行。
def _write_reproduction(
    folder: Path,
    finding: Finding,
    loc: SourceLocation,
    kind: str,
    cmd: str,
    input_text: str,
    wrong: str,
    right: str,
    compile_cmd: str | None = None,
) -> None:
    _attach_poc_chain(finding, loc, kind, cmd, input_text, wrong, right)
    lines = [
        "# 本地 CWE 演示（不是设备利用）",
        "",
        f"- 告警 id：{finding.id}",
        f"- CWE：{finding.cwe_id or '无'}",
        f"- sink：{finding.sink or finding.title}",
        f"- 函数：{loc.function or '无'}",
        f"- 源码：{loc.path}:{loc.start_line}",
        f"- 演示类型：{kind}",
        "",
        "## 输入",
        "",
        input_text,
        "",
        "## 错误行为",
        "",
        wrong,
        "",
        "## 正确边界",
        "",
        right,
        "",
        "## 如何运行",
        "",
        f"`{cmd}`",
        "",
    ]
    if compile_cmd:
        lines.extend(
            [
                "编译并在本进程触发（不访问设备）：",
                "",
                f"`{compile_cmd}`",
                "",
            ]
        )
    lines.extend(
        [
            "C 程序退出码 0 表示缺陷行为已在本地触发。",
            "poc_status 不得标为 verified。",
            "",
        ]
    )
    (folder / "reproduction.md").write_text("\n".join(lines), encoding="utf-8")


# 结构化证据链写入 extra.poc，供报告页渲染；不要只把 stdout 当成全部证据。
def _attach_poc_chain(
    finding: Finding,
    loc: SourceLocation,
    kind: str,
    cmd: str,
    input_text: str,
    wrong: str,
    right: str,
) -> None:
    loc_text = f"{loc.path}:{loc.start_line}"
    func = loc.function or "无"
    finding.extra["poc"] = {
        "kind": kind,
        "cmd": cmd,
        "input": input_text,
        "wrong": wrong,
        "right": right,
        "function": loc.function,
        "source": loc_text,
        "note": "本地 CWE 演示，未在设备执行，不是已验证利用",
        "steps": [
            {
                "title": "1. 汇点",
                "detail": f"{finding.sink or finding.title} · {loc_text} · {func}",
            },
            {"title": "2. 演示输入", "detail": input_text},
            {"title": "3. 错误行为（当前代码）", "detail": wrong},
            {"title": "4. 正确边界", "detail": right},
            {"title": "5. 本地命令", "detail": cmd},
        ],
    }


# 说明本目录用途，避免把截段误当成已验证利用。
def _poc_notes(finding: Finding, loc: SourceLocation, extra_lines: list[str]) -> list[str]:
    notes = [
        f"id: {finding.id}",
        f"cwe: {finding.cwe_id or '无'}",
        f"function: {loc.function or '无'}",
        f"source: {loc.path}:{loc.start_line}",
        "本目录是告警处原文截段，供后续编写 CWE 演示，不是已验证利用。",
        "poc_status 不得标为 verified。",
        "",
    ]
    notes.extend(extra_lines)
    return notes


# 按 sink 选模板、填槽、落盘；Python 演示扫描时执行，C 演示仅在有编译器时附加跑一次。
def _emit_harness(
    ctx: ScanContext,
    finding: Finding,
    loc: SourceLocation,
    folder: Path,
    notes: list[str],
) -> None:
    sink = finding.sink or finding.title or ""
    source_text = _read_source_file(Path(ctx.request.source), loc.path)
    snippet = loc.snippet or ""

    if sink in _PREFIX_SINKS:
        prefix, origin = extract_path_prefix(snippet, source_text)
        demo = folder / "prefix_boundary_demo.py"
        demo.write_text(
            _fill(_load_template("cwe22_prefix.py.txt"), {"PREFIX_LIT": _py_lit(prefix)}),
            encoding="utf-8",
        )
        c_name = "prefix_boundary_demo.c"
        (folder / c_name).write_text(
            _fill(_load_template("cwe22_prefix.c.txt"), {"PREFIX_LIT": _c_lit(prefix)}),
            encoding="utf-8",
        )
        compile_cmd = _compile_hint(c_name)
        finding.poc_cmd = "python prefix_boundary_demo.py"
        finding.extra["poc_kind"] = "cwe-22-prefix"
        finding.extra["poc_prefix"] = prefix
        finding.extra["poc_prefix_origin"] = origin
        finding.extra["poc_c_cmd"] = compile_cmd
        notes.append(f"CWE-22 前缀复现：{compile_cmd}（常量来源 {origin}，不访问设备）")
        _write_reproduction(
            folder,
            finding,
            loc,
            "cwe-22-prefix",
            finding.poc_cmd,
            f"`{prefix}X/secret`",
            f"`find({prefix!r})==0` 会把兄弟目录当成沙箱。",
            f"比较 `{prefix}/`，或使用本应用 baseDir。",
            compile_cmd,
        )
        return

    if sink in _CONCAT_SINKS:
        base, origin = extract_concat_base(snippet, source_text)
        demo = folder / "path_concat_demo.py"
        demo.write_text(
            _fill(_load_template("cwe22_concat.py.txt"), {"BASE_LIT": _py_lit(base)}),
            encoding="utf-8",
        )
        c_name = "path_concat_demo.c"
        (folder / c_name).write_text(
            _fill(_load_template("cwe22_concat.c.txt"), {"BASE_LIT": _c_lit(base)}),
            encoding="utf-8",
        )
        compile_cmd = _compile_hint(c_name)
        finding.poc_cmd = "python path_concat_demo.py"
        finding.extra["poc_kind"] = "cwe-22-concat"
        finding.extra["poc_prefix"] = base
        finding.extra["poc_prefix_origin"] = origin
        finding.extra["poc_c_cmd"] = compile_cmd
        notes.append(f"CWE-22 拼接复现：{compile_cmd}（不 fopen）")
        _write_reproduction(
            folder,
            finding,
            loc,
            "cwe-22-concat",
            finding.poc_cmd,
            f"用户片段 `../other_app/secret.txt`，基目录 `{base}`",
            "拼接后再规范化可落到 sandbox 之外。",
            "先规范化，再确认结果仍以 sandbox 为前缀且落在分隔符上。",
            compile_cmd,
        )
        return

    if sink in _CMD_SINKS:
        demo = folder / "command_concat_demo.py"
        demo.write_text(
            _fill(_load_template("cwe78_noexec.py.txt"), {"USER_LIT": _py_lit(_DEFAULT_USER)}),
            encoding="utf-8",
        )
        c_name = "command_concat_demo.c"
        (folder / c_name).write_text(
            _fill(_load_template("cwe78_noexec.c.txt"), {"USER_LIT": _c_lit(_DEFAULT_USER)}),
            encoding="utf-8",
        )
        compile_cmd = _compile_hint(c_name)
        finding.poc_cmd = "python command_concat_demo.py"
        finding.extra["poc_kind"] = "cwe-78-noexec"
        finding.extra["poc_c_cmd"] = compile_cmd
        notes.append(f"CWE-78 复现：{compile_cmd}（只检查 shell 字符串，不执行）")
        _write_reproduction(
            folder,
            finding,
            loc,
            "cwe-78-noexec",
            finding.poc_cmd,
            f"用户片段 `{_DEFAULT_USER}`",
            "拼进 `ls ` + user 后，整串会进 system()/Runtime.exec。",
            "改用 argv 数组（execve / ProcessBuilder 列表），不要拼 shell 字符串。",
            compile_cmd,
        )
        return

    if sink in _COPY_SINKS:
        demo = folder / "buffer_copy_demo.py"
        demo.write_text(_load_template("cwe120_copy.py.txt"), encoding="utf-8")
        c_name = "buffer_copy_demo.c"
        (folder / c_name).write_text(_load_template("cwe120_overflow.c.txt"), encoding="utf-8")
        compile_cmd = _compile_hint(c_name)
        finding.poc_cmd = "python buffer_copy_demo.py"
        finding.extra["poc_kind"] = "cwe-120-copy"
        finding.extra["poc_c_cmd"] = compile_cmd
        notes.append(f"CWE-120 复现：{compile_cmd}（canary 被改写即触发）")
        _write_reproduction(
            folder,
            finding,
            loc,
            "cwe-120-copy",
            finding.poc_cmd,
            "源串 15 字节加 NUL，目标容量 8 字节，相邻 8 字节 canary。",
            "拷贝长度用 strlen(src)+1，改写 canary。有界拷贝保持 canary。",
            "长度取 min(源长, 目标容量-1)，并显式写入终止符。",
            compile_cmd,
        )
        return

    if sink in _FORMAT_SINKS:
        demo = folder / "format_string_demo.py"
        demo.write_text(_load_template("cwe134_format.py.txt"), encoding="utf-8")
        c_name = "format_string_demo.c"
        (folder / c_name).write_text(_load_template("cwe134_format.c.txt"), encoding="utf-8")
        compile_cmd = _compile_hint(c_name)
        finding.poc_cmd = "python format_string_demo.py"
        finding.extra["poc_kind"] = "cwe-134-format"
        finding.extra["poc_c_cmd"] = compile_cmd
        notes.append(f"CWE-134 复现：{compile_cmd}（用户串被解释成格式）")
        _write_reproduction(
            folder,
            finding,
            loc,
            "cwe-134-format",
            finding.poc_cmd,
            '用户串 `"marker=%d"`，对应参数为 7。',
            "把用户串当格式时输出 marker=7；当普通文本时仍是 marker=%d。",
            '格式串必须是字面量：printf("%s", user)。',
            compile_cmd,
        )
        return

    finding.poc_cmd = "captured original snippet; CWE harness not run"
    finding.extra["poc_kind"] = "snippet-only"
    notes.append("无对应 CWE 模板，只保留原文截段。")


# 落盘后跑 Python。有 .c 且本机有编译器时必须编译并跑通，否则记 failed。
def _run_emitted(finding: Finding, folder: Path) -> None:
    cmd = finding.poc_cmd or ""
    if not cmd.startswith("python "):
        finding.extra["poc_ran"] = False
        return
    demo_name = cmd.split(None, 1)[1]
    demo = folder / demo_name
    if not demo.is_file():
        finding.poc_status = PocStatus.FAILED
        finding.evidence = f"missing {demo_name}"
        finding.extra["poc_ran"] = False
        return
    ok, out = _run_python(demo)
    finding.evidence = out or None
    finding.extra["poc_ran"] = ok
    chain = finding.extra.get("poc")
    if isinstance(chain, dict):
        chain["ran"] = ok
        steps = list(chain.get("steps") or [])
        if out:
            steps.append({"title": "6. 演示输出", "detail": out})
        chain["steps"] = steps
    if not ok:
        finding.poc_status = PocStatus.FAILED
        return
    c_files = sorted(folder.glob("*.c"))
    if not c_files:
        return
    c_ok, c_out = _try_compile_c(c_files[0])
    finding.extra["poc_c_ran"] = c_ok
    finding.extra["poc_c_cmd"] = _compile_hint(c_files[0].name)
    if c_out and c_out != "no C compiler":
        extra_ev = (finding.evidence or "") + ("\n" + c_out if finding.evidence else c_out)
        finding.evidence = extra_ev[-4000:]
        chain = finding.extra.get("poc")
        if isinstance(chain, dict):
            steps = list(chain.get("steps") or [])
            steps.append({"title": "7. 编译触发", "detail": c_out})
            chain["steps"] = steps
    if c_out == "no C compiler":
        finding.extra["poc_c_note"] = "no C compiler"
        return
    if not c_ok:
        finding.poc_status = PocStatus.FAILED


# 只落盘原文和按 sink 的 CWE 演示；状态只能是 generated/skipped/failed，禁止 verified。
def run_poc(ctx: ScanContext) -> None:
    poc_root = ctx.work_dir / "poc"
    poc_root.mkdir(parents=True, exist_ok=True)
    for finding in ctx.findings:
        loc = finding.locations[0] if finding.locations else None
        if loc is None:
            finding.poc_status = PocStatus.SKIPPED
            finding.poc_path = None
            continue
        slice_ = _snippet_for(ctx, loc.path, loc.start_line, loc.snippet)
        if not slice_.snippet:
            finding.poc_status = PocStatus.SKIPPED
            finding.poc_path = None
            continue
        loc.snippet = slice_.snippet
        if slice_.function:
            loc.function = slice_.function
        if slice_.end_line:
            loc.end_line = slice_.end_line
        folder = poc_root / _safe_dir_name(finding.id)
        folder.mkdir(parents=True, exist_ok=True)
        snippet_file = folder / "original_snippet.txt"
        snippet_file.write_text(slice_.snippet, encoding="utf-8")
        notes: list[str] = []
        _emit_harness(ctx, finding, loc, folder, notes)
        (folder / "README.txt").write_text("\n".join(_poc_notes(finding, loc, notes)), encoding="utf-8")
        finding.poc_status = PocStatus.GENERATED
        finding.poc_path = str(snippet_file)
        finding.extra["poc_dir"] = str(folder)
        _run_emitted(finding, folder)
        if finding.poc_status is PocStatus.VERIFIED:
            finding.poc_status = PocStatus.GENERATED
