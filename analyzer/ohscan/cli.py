"""评委/无 UI 入口。Web 只是这组命令的外壳。

默认每次 scan 会清空仓库根目录下的 artifacts/，只保留本次 --out。
需要对照历史扫描时加 --keep-artifacts。
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import typer

from ohscan.models.finding import ScanRequest
from ohscan.pipeline import ScanContext, run_scan

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ARTIFACTS = _REPO_ROOT / "artifacts"

app = typer.Typer(help="OHSleuth OpenHarmony vulnerability analyzer")


# 清空仓库 artifacts/，避免上次扫描结果混进本次 --out。
def _clear_previous_scans(out: Path) -> None:
    if _ARTIFACTS.exists():
        for child in _ARTIFACTS.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    out.mkdir(parents=True, exist_ok=True)


# 把 --since/--until 从 ISO 字符串转成 datetime；空值表示不限窗口。
def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


# 静态扫描入口：引擎→研判→报告→（可选）模型第二裁判。
# 未配模型时 review 节点跳过。单独重跑仍可用：python -m ohscan review --out ...
@app.command()
def scan(
    source: str = typer.Option(..., "--src", help="Local source tree or repo path"),
    out: Path = typer.Option(Path("artifacts/local"), "--out", help="Artifact directory"),
    engines: str = typer.Option("semgrep", "--engines", help="Comma-separated engine names"),
    since: str | None = typer.Option(None, "--since", help="ISO time window start, e.g. 2025-01-01"),
    until: str | None = typer.Option(None, "--until", help="ISO time window end"),
    branches: str = typer.Option("", "--branches", help="Comma-separated branch names"),
    subsystems: str = typer.Option("", "--subsystems", help="Comma-separated OH subsystems"),
    enable_poc: bool = typer.Option(
        True,
        "--poc/--no-poc",
        help="默认生成原文截段和 CWE-22 字符串演示；不需要时 --no-poc",
    ),
    enable_fix: bool = typer.Option(True, "--fix/--no-fix"),
    enable_review: bool = typer.Option(
        True,
        "--review/--no-review",
        help="报告写完后跑模型第二裁判；未配模型则跳过。不需要时 --no-review",
    ),
    keep_artifacts: bool = typer.Option(
        False,
        "--keep-artifacts",
        help="Do not delete previous folders under artifacts/",
    ),
) -> None:
    if keep_artifacts:
        out.mkdir(parents=True, exist_ok=True)
    else:
        _clear_previous_scans(out)
    request = ScanRequest(
        source=source,
        out_dir=out,
        engines=[item.strip() for item in engines.split(",") if item.strip()],
        since=_parse_time(since),
        until=_parse_time(until),
        branches=[item.strip() for item in branches.split(",") if item.strip()],
        subsystems=[item.strip() for item in subsystems.split(",") if item.strip()],
        enable_poc=enable_poc,
        enable_fix=enable_fix,
        enable_review=enable_review,
    )
    ctx = ScanContext(request=request, work_dir=out)
    run_scan(ctx)
    typer.echo(
        f"scan complete: {len(ctx.findings)} accepted, "
        f"{len(ctx.rejected)} rejected -> {out}"
    )


# 把上次 scan 写出的 report.md 打到 stdout，给评委快速查看。
@app.command()
def report(
    out: Path = typer.Option(Path("artifacts/local"), "--out"),
) -> None:
    report_file = out / "report" / "report.md"
    if not report_file.exists():
        raise typer.BadParameter(f"missing {report_file}, run scan first")
    typer.echo(report_file.read_text(encoding="utf-8"))


# 动态第二裁判：读 report.json，写 extra.dynamic。未配模型则跳过。
@app.command()
def review(
    out: Path = typer.Option(Path("artifacts/local"), "--out"),
) -> None:
    from ohscan.dynamic.runtime import run_dynamic

    report_json = out / "report" / "report.json"
    if not report_json.exists():
        raise typer.BadParameter(f"missing {report_json}, run scan first")
    result = run_dynamic(report_json)
    reason = result.get("reason") or ""
    typer.echo(
        f"review {result.get('status')}: reviewed={result.get('reviewed', 0)}"
        + (f" {reason}" if reason else "")
        + f" -> {report_json}"
    )


if __name__ == "__main__":
    app()
