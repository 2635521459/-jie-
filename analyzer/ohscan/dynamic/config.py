"""动态配置：只给 review 用。静态 DAG 不得 import 本模块。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "knowledge" / "dynamic" / "config.yml"


@dataclass
class DynamicConfig:
    enabled: bool
    provider: str
    base_url: str
    model: str
    api_key: str
    max_tool_rounds: int
    timeout_seconds: int
    # 默认 False：reject 只写 extra.dynamic，不从正式 findings 删除。
    apply_verdict_to_accepted: bool = False


# 读 yml；OHSCAN_API_KEY / OHSCAN_DYNAMIC_ENABLED 覆盖文件里的值。
def load_config(path: Path | None = None) -> DynamicConfig:
    target = path or _CONFIG_PATH
    data: dict = {}
    if target.exists():
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    enabled = bool(data.get("enabled", False))
    env_enabled = os.environ.get("OHSCAN_DYNAMIC_ENABLED", "").strip().lower()
    if env_enabled in {"1", "true", "yes"}:
        enabled = True
    if env_enabled in {"0", "false", "no"}:
        enabled = False
    api_key = str(os.environ.get("OHSCAN_API_KEY") or data.get("api_key") or "").strip()
    return DynamicConfig(
        enabled=enabled,
        provider=str(data.get("provider") or "openai_compat"),
        base_url=str(data.get("base_url") or "").rstrip("/"),
        model=str(data.get("model") or ""),
        api_key=api_key,
        max_tool_rounds=int(data.get("max_tool_rounds") or 4),
        timeout_seconds=int(data.get("timeout_seconds") or 60),
        apply_verdict_to_accepted=bool(data.get("apply_verdict_to_accepted", False)),
    )


# 只有显式打开且具备模型名时才真正请求；否则 review 跳过。
def config_ready(cfg: DynamicConfig) -> bool:
    if not cfg.enabled:
        return False
    if not cfg.model:
        return False
    return True
