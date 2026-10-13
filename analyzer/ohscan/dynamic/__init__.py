"""动态阶段：模型第二裁判 + 只读工具。引擎/triage 不得 import；DAG 只通过 stage.py 在 report 之后接入。"""

from ohscan.dynamic.config import load_config
from ohscan.dynamic.runtime import run_dynamic

__all__ = ["load_config", "run_dynamic"]
