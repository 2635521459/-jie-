"""引擎包。对外只暴露 run_*；当前唯一检测引擎是 Semgrep。"""

from ohscan.engines.base import Engine
from ohscan.engines.merge import run_merge
from ohscan.engines.semgrep_engine import run_semgrep

__all__ = ["Engine", "run_merge", "run_semgrep"]
