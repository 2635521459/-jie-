

"""OHSleuth 分析引擎包（唯一检测路径）。

静态：locate → semgrep → merge/triage → deliver（report.json）。
动态：ohscan.dynamic，只在 report 之后由 stage 接入；不要从引擎/triage import。
评委无 UI：`python -m ohscan scan --src <仓> --out artifacts/demo`
"""

__version__ = "0.1.0"
