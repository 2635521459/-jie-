# OHSleuth

OpenHarmony 开源代码自动化漏洞分析工具。评委可以不启动 Web，只用 CLI 跑完整扫描并出报告。

当前仓库已经接通：**读仓 → 分类索引 → 引擎扫描 → 去重 → 研判 → 富化/影响范围 → 可选 PoC/修复 → 报告 → 模型第二裁判**。  
准确性优先于数量：不把功能缺陷、空指针、测试代码当安全漏洞；没有公开编号就不上报 CVE。

## 三层结构

| 层 | 目录 | 作用 |
|----|------|------|
| 前端 | `frontend/` | 浏览器 :5173，建任务、看进度和报告 |
| 后端 | `backend/` | FastAPI :8000，只记任务、读 artifacts，不在 HTTP 里跑引擎 |
| 分析引擎 | `analyzer/ohscan` | 唯一检测路径：`python -m ohscan scan` |

规则和知识在 `knowledge/`，不写进 React。所有层共用 `Finding`（`analyzer/ohscan/models/finding.py`）。

## 分析流水线（现在实际在做什么）

```
ingest → index → semgrep
       → merge → triage → enrich / impact（并行）
       → poc / fix（可选） → report → review（第二裁判，未配模型则跳过）
```

一次扫描的产物在 `--out` 目录（例如 `artifacts/<job_id>/`）：`repo_meta.json`、`file_index.json`、`raw/<engine>.jsonl`、`merged.jsonl`、`accepted.jsonl`、`rejected.jsonl`、`report/report.json`、`report/report.md`。模型只读已写出的 `report.json`，把结论写回 `extra.dynamic`。

### 1. 读取源码（ingest）

从**本地目录**接入，不在流水线里 clone 官网仓库。校验路径存在后，采集 git 分支 / HEAD / `describe --tags --always` / 可选时间窗变更文件，写入 `repo_meta.json`。不列源文件、不扫漏洞。

### 2. 分类索引（index）

遍历源码树（可按时间窗增量），只收 `.c/.cc/.cpp/.h/.hpp/.java/.ts/.ets`，跳过 `.git`、`node_modules`、`prebuilts` 等。  
按 `knowledge/oh_modules.yml` 的路径前缀把文件归到子系统（kernel、communication、hiviewdfx 等），写出 `file_index.json`。这一步只做归属，不判漏洞。

### 3. 引擎扫描

`index` 之后只跑 **Semgrep**，只产出原始 `Finding`，**不在这里填 CVE、不做是否为漏洞的最终判定**。研判在 merge 之后才做。规则在 `knowledge/rules/semgrep/`。

调用本机 `pysemgrep`/`semgrep`。命中带位置、CWE、片段。置信度来自规则 `metadata.confidence`：未写时为 medium。标成 `low` 的命中会被研判以 `below confidence threshold` 排除出正式报告，留在 `rejected.jsonl`。模型第二轮仍会给这些低置信度告警写 `extra.dynamic`，但不会把它们放回正式名单。CWE 编号和名字来自规则 `metadata`，对应关系如下：

| 规则 | 命中模式 | `cwe_id` | `cwe_name` |
|------|----------|----------|------------|
| `oh.strcpy-unbounded` | `strcpy` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.strcat-unbounded` | `strcat` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.sprintf-unbounded` | `sprintf` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.gets` | `gets` | CWE-242 | Use of Inherently Dangerous Function |
| `oh.memcpy-strlen` | `memcpy`/`memmove` + `strlen(src)` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.vsprintf-unbounded` | `vsprintf` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.scanf-unbounded-s` | `scanf`/`fscanf`/`sscanf` 的 `%s` | CWE-120 | Buffer Copy without Checking Size of Input |
| `oh.printf-format-string` | 非字面量格式串 | CWE-134 | Use of Externally-Controlled Format String |
| `oh.system-command` | 非字面量 `system` | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |
| `oh.popen-command` | 非字面量 `popen` | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |
| `oh.path-find-prefix` | `path.find(prefix) == 0`（排除 `file://`、`file://docs/`、`/` 等 URI/绝对路径分类） | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| `oh.strncmp-path-prefix` | `strncmp(path, prefix, strlen(prefix)) == 0`（变量名不含裸 `name`） | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| `oh.fopen-concat` | 仅 `fopen(dir + name)` 拼接 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| `oh.open-concat` | 拼接路径 `open` | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| `oh.alloc-mul-size` | `malloc(a * b)` 或 `new T[a * b]`，两个因子都不是 `sizeof` | CWE-190 | Integer Overflow or Wraparound |
| `oh.java-array-mul-size` | `new T[a * b]` | CWE-190 | Integer Overflow or Wraparound |
| `oh.log-secret-name` | `printf` / `HILOG` / `HILOGE` / `HILOGI` 的参数名像密钥 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| `oh.java-log-secret-name` | `Log` / logger 的参数名像密钥 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| `oh.double-free-adjacent` | 相邻两行对同一指针 `free` 或 `delete` | CWE-415 | Double Free |
| `oh.double-free` | 同一指针两次释放，中间隔了其他语句，且没有赋空 | CWE-415 | Double Free |

不报 `strncpy` / `snprintf` / `fgets`、带目标 `sizeof` 的 `memcpy`，字面量 `system("...")` / `printf("%s", ...)` / `fopen("...")`，以及 `path.find("file://")`、单独的 `fopen(fileName)`。也不报 `malloc(n * sizeof(T))`、中间已经写成 `NULL` / `nullptr` 的第二次释放，以及参数名不像密钥的普通日志。

这几类和准确率的关系：

- **CWE-190 整数溢出**：只匹配分配大小由两个非常量因子相乘得到的写法。Semgrep 看不到前面有没有上限检查，所以置信度是 `low`，不进正式报告。
- **CWE-787 堆/栈边界**：任意变量长度的 `memcpy` / `memmove` 不新增规则。现有 `oh.memcpy-strlen` 只报长度来自 `strlen(源)` 的复制，编号仍是 CWE-120。
- **CWE-200 信息泄露**：只匹配参数文本里带 `password`、`passwd`、`token`、`secret`、`api_key` 的日志。未初始化缓冲不扫。置信度是 `low`。
- **CWE-415 重复释放**：相邻两行的 `free(p); free(p);` 或 `delete` 置信度是 `medium`，可以进入正式报告。中间隔了语句、或处在 `if/else` 两个分支里的，仍是 `low`，不进正式报告。两次释放之间已经写成 `NULL` 或 `nullptr` 的不报。
- **CWE-416 释放后使用**：不扫。释放后的同名使用分不清是重新赋值还是悬空使用。
- **CWE-269 权限检查缺失**：不扫。敏感操作和 `CheckPermission` / `VerifyAccessToken` 经常不在同一个函数里，当前函数看不到检查就会误报。

Semgrep 命中时会带上 CWE 编号和名字，一条告警大致如下：

```json
{
  "id": "semgrep:oh.strcpy-unbounded:foo/bar.c:42",
  "title": "oh.strcpy-unbounded",
  "summary": "Unbounded strcpy may overflow the destination buffer.",
  "cwe_id": "CWE-120",
  "cwe_name": "Buffer Copy without Checking Size of Input",
  "cve_ids": [],
  "severity": "high",
  "confidence": "medium",
  "locations": [
    {
      "path": "foo/bar.c",
      "start_line": 42,
      "snippet": "strcpy(dst, src);"
    }
  ],
  "sink": "oh.strcpy-unbounded",
  "subsystem": "hiviewdfx",
  "engines": ["semgrep"]
}
```

某次扫描 0 条命中表示规则没匹配到，不等于流水线失败。

### 4. 合并去重（merge）

读取 `raw/*.jsonl`，按「文件路径 + 行号 + CWE」去重。同一位置有多条时保留置信度更高的那条，并把 `engines` 列表合并。结果写入 `merged.jsonl`。

### 5. 研判（triage）

规则闸门，不是 LLM。对 merge 后的每条告警按顺序检查三道硬条件，**命中任意一条就丢弃**，不进正式报告：

| 顺序 | 条件 | 落盘原因 |
|------|------|----------|
| 1 | 置信度低于门槛（默认要求 medium 及以上） | `below confidence threshold` |
| 2 | 没有源码位置（无文件和行号） | `missing source location` |
| 3 | 路径落在测试 / 示例 / fuzz 目录（`/test/`、`/unittest/`、`/fuzz/` 等） | `test or fuzz path` |

通过的进入 `accepted.jsonl` 并继续后续阶段；被拒的进入 `rejected.jsonl`（带 `fp_reason`），只供误报审计。  
研判**不发现**漏洞，只决定已有告警能不能上报。

### 6. 富化与影响范围（enrich / impact，并行）

- **enrich**：规则没带 CWE 时按标题关键词补一层；CVE **不联网、不调外部库**。只读 `knowledge/cve/fingerprints.json`。一行必须同时有具体源文件、函数名，以及引擎已经实现的 `cwe_id`（CWE-22、CWE-78、CWE-120、CWE-134、CWE-242、CWE-190、CWE-200、CWE-415）。三者对齐才抄 `cve_ids` 和公告里的 `affected_versions`。同一条告警命中多行时不抄编号。公告里没有路径遍历、命令注入、格式化字符串、`gets`、无界复制的自研条目；一次修复改了很多函数的公告也没有写入。对不上的洞留空，禁止猜测编号。
- **impact**：根据索引和 `repo_meta.json` 填模块、子系统、当前分支。指纹没给出版本时，用本次扫描的 tag/HEAD 填 `affected_versions`，并标明 `version_basis=scanned_revision`。跨分支 checkout 验证尚未做。

### 7. 可选 PoC 与修复（poc / fix）

默认开启 PoC；不需要时 CLI 加 `--no-poc`，网页取消勾选。阶段失败也不让整次扫描崩溃。`poc_status` 只能是 `generated` / `skipped` / `failed`，禁止 `verified`。不调模型生成利用。

- **poc**：按告警行从源码重读函数，写入 `poc/<finding-id>/`。再按 sink 填充 `knowledge/poc` 模板。扫描时先跑 Python。有 gcc/clang 时用 `-O0 -std=c11` 编译同目录 `.c` 并运行：前缀误接受、路径逃出、canary 被改写、格式串被解释，退出码 0 才算本地触发。命令类只检查 shell 字符串，不调用 `system`。没有编译器时 Python 结果仍然有效。
- **fix**：按 sink 写占位建议；正式报告还不能当补丁用。

### 8. 写报告（report）

只使用研判通过的 findings，写出 `report/report.json`（机器/模型契约）和 `report/report.md`（人读投影）。CVE 对不上则 JSON 为 `[]`、Markdown 写「无」。

### 9. 模型第二裁判（review）

默认挂在 `report` 之后。本地先预取整函数、调用点和文件头常量，再把卷宗交给模型裁决；缺事实才允许再调工具。结论写入 `extra.dynamic`。不发现新漏洞，不编造 CVE，不把 PoC 标成 verified。非法裁决记为 downgrade。

正式报告里的告警都会审。提示词里的专用检查点覆盖 CWE-22、CWE-78、CWE-120、CWE-242、CWE-134、CWE-190、CWE-200、CWE-415。另外，`rejected.jsonl` 里原因是 `below confidence threshold` 的低置信度告警也会审，但只把结论写回该文件的 `extra.dynamic`，不放进正式名单。没有正式告警、也没有这类低置信度告警，或未配置模型时，这一阶段跳过。不需要时 CLI 加 `--no-review`。对已有报告补跑：`python -m ohscan review --out artifacts/request`。

## 接下来要补的内容

按准确性优先，不要先接 LLM 或 CodeQL 来「刷数」。

1. **Semgrep 规则包**（已写入 `dangerous-copy.yml` / `unbounded-copy.yml` / `format-string.yml` / `command-exec.yml` / `path-traversal.yml` / `integer-overflow.yml` / `info-leak-log.yml` / `double-free.yml`）。相邻两次释放是 `medium`；CWE-190、CWE-200，以及中间隔了语句的 CWE-415 仍是 `low`。CWE-787 的任意长度复制、CWE-416、CWE-269 未接入。
2. **样本路径规则已复核**（request 的 AREA 留下，URI/`find('/')` 丢掉；appspawn/hilog 测试命中进 rejected）。
3. **按官方公告 + 修复 commit 填写 CVE 指纹**：一条 CVE 对应文件/函数/CWE/受影响版本。不要把 NVD 整表倒进 `fingerprints.json`。
4. **动态阶段已挂进 DAG**（`report` 之后的 `review`）：模型只当第二裁判；不要把 LLM 当第一检测器。

## 本地运行

分析引擎（不需要前端）：

```powershell
cd C:\Users\26355\Desktop\OHSleuth
python -m pip install -e ".[web,dev]"
python -m ohscan scan --src C:\path\to\code --out artifacts\demo
```

默认会先清空仓库里的 `artifacts/`（`hilog-check`、`appspawn-path` 等旧目录都会删掉），只保留本次 `--out`。对照历史结果时加 `--keep-artifacts`。

后端：

```powershell
$env:PYTHONPATH = "C:\Users\26355\Desktop\OHSleuth\analyzer;C:\Users\26355\Desktop\OHSleuth\backend"
python backend\run.py
```

前端：

```powershell
cd frontend
npm install
npm run dev
```

可视化报告（推荐测试方式）：先起前后端，再跑 pytest。默认打开 http://127.0.0.1:5173/ 的「报告」页（任务 `request`）。

```powershell
python -m pip install -e ".[web,dev]"
cd frontend; npm install; cd ..
python scripts/start_web.py --pytest
```

