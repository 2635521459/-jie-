"""漏洞数据契约：分析引擎、后端 API、报告模板共用这一份模型。

规划：
- 赛题报告字段全部映射到 Finding，禁止前端再拼一套结构。
- 引擎只填「原始告警」相关字段；CWE/CVE、影响、PoC、修复由后续阶段补全。
- 改字段时同步改 deliver.py 和前端详情页，保持三层一致。
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """严重程度，后续用 CVSS 映射，不要只靠引擎默认值。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """内部置信度。低于阈值的告警进 rejected，不进正式报告（控误报）。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PocStatus(str, Enum):
    """PoC 与报告解耦：未生成也能出报告，状态写 SKIPPED/FAILED 即可。"""

    NOT_STARTED = "not_started"
    GENERATED = "generated"
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


class SourceLocation(BaseModel):
    """赛题「源码位置与内容」。snippet 必须带上下文，不能只给行号。"""

    path: str
    start_line: int
    end_line: int | None = None
    function: str | None = None
    snippet: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    summary: str  # 简要描述：触发条件 + 影响路径
    cwe_id: str | None = None  # 赛题：CWE 分类，enrich 阶段补全
    cwe_name: str | None = None
    cve_ids: list[str] = Field(default_factory=list)  # 已公开才填，禁止猜测
    severity: Severity = Severity.MEDIUM
    cvss: float | None = None
    confidence: Confidence = Confidence.MEDIUM
    locations: list[SourceLocation] = Field(default_factory=list)
    source: str | None = None  # 污点源 / 攻击入口
    sink: str | None = None  # 危险点（拷贝、free、权限检查等）
    trace: list[str] = Field(default_factory=list)  # 影响路径
    module: str | None = None  # 代码模块（仓内目录）
    subsystem: str | None = None  # OH 功能子系统，见 knowledge/oh_modules.yml
    attack_surface: str | None = None  # 对外接口 / 驱动 ioctl / IPC 等
    affected_versions: list[str] = Field(default_factory=list)
    affected_branches: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)  # 哪些引擎命中，供融合计分
    poc_status: PocStatus = PocStatus.NOT_STARTED
    poc_path: str | None = None
    poc_cmd: str | None = None
    evidence: str | None = None  # 本地 CWE 演示 stdout；不是设备崩溃日志
    fix_advice: str | None = None
    patch_diff: str | None = None
    fp_reason: str | None = None  # 被研判丢弃时填写，方便审计误报策略
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    """一次扫描的输入。时间窗/子系统是大规模 OH 多仓扫描的裁剪开关。"""

    source: str  # 本地源码根目录；后续支持 manifest/repo
    out_dir: Path
    since: datetime | None = None  # 指定时间段增量（赛题交付要求）
    until: datetime | None = None
    branches: list[str] = Field(default_factory=list)  # 跨分支影响分析
    subsystems: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=lambda: ["semgrep"])
    min_confidence: Confidence = Confidence.MEDIUM
    enable_poc: bool = True  # 默认开：截段和 CWE 演示；不得把状态写成 verified
    enable_fix: bool = True
    # 默认开：报告写完后跑第二裁判。未配模型则跳过，不发现新洞、不改 CVE/PoC。
    enable_review: bool = True
    jobs: int = 4  # 引擎内部并行度，下一步才真正用上
