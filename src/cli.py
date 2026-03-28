"""memhuntr CLI — Memory forensics malware classifier."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .extraction import check_volatility, extract_features
from .inference import explain_prediction, load_pipeline, predict

app = typer.Typer(
    name="memhuntr",
    help="Classify memory dumps as Benign or Malware (Ransomware/Spyware/Trojan) "
    "using Volatility 3 features and a two-stage XGBoost pipeline.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    dump_path: Path = typer.Argument(
        ...,
        help="Path to the memory dump file (.raw, .vmem, etc.)",
        exists=True,
        readable=True,
    ),
    model_dir: Optional[Path] = typer.Option(
        None,
        "--model-dir",
        "-m",
        help="Override model directory (default: bundled temporal models).",
    ),
    vol_path: str = typer.Option(
        "vol",
        "--vol-path",
        help="Path to Volatility 3 executable.",
    ),
    output_format: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Output format: 'table' (rich) or 'json'.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        "-e",
        help="Show top features driving the prediction.",
    ),
    timeout: int = typer.Option(
        600,
        "--timeout",
        "-t",
        help="Max seconds per Volatility plugin.",
    ),
):
    """Scan a memory dump and classify it as Benign or Malware."""
    # Validate Volatility
    try:
        vol_cmd = check_volatility(vol_path)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    # Load models
    try:
        pipeline = load_pipeline(model_dir)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    # Extract features
    console.print(f"\n[bold]Scanning:[/bold] {dump_path.name}\n")

    def on_progress(plugin, status):
        if status == "running":
            console.print(f"  [dim]Running {plugin}...[/dim]", end="")
        elif status == "done":
            console.print(f" [green]done[/green]")
        else:
            console.print(f" [yellow]{status}[/yellow]")

    try:
        features_df = extract_features(str(dump_path), vol_cmd, timeout, on_progress)
    except Exception as e:
        console.print(f"\n[red]Feature extraction failed: {e}[/red]")
        raise typer.Exit(1)

    # Predict
    result = predict(features_df, pipeline)

    # Explain
    explanation = None
    if explain:
        explanation = explain_prediction(features_df, pipeline)

    # Output
    if output_format == "json":
        out = {**result}
        if explanation:
            out["explanation"] = explanation
        console.print(json.dumps(out, indent=2))
    else:
        _display_result(result, explanation)


@app.command()
def info(
    dump_path: Path = typer.Argument(
        ...,
        help="Path to the memory dump file.",
        exists=True,
        readable=True,
    ),
    vol_path: str = typer.Option(
        "vol",
        "--vol-path",
        help="Path to Volatility 3 executable.",
    ),
):
    """Detect OS information for a memory dump (replaces Vol2 imageinfo)."""
    try:
        vol_cmd = check_volatility(vol_path)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing:[/bold] {dump_path.name}\n")

    try:
        result = subprocess.run(
            [vol_cmd, "-f", str(dump_path), "windows.info"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        console.print(result.stdout)
        if result.returncode != 0:
            console.print(f"[yellow]{result.stderr}[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("[red]windows.info timed out (300s)[/red]")
        raise typer.Exit(1)


@app.command()
def check(
    vol_path: str = typer.Option(
        "vol",
        "--vol-path",
        help="Path to Volatility 3 executable.",
    ),
    model_dir: Optional[Path] = typer.Option(
        None,
        "--model-dir",
        "-m",
        help="Override model directory.",
    ),
):
    """Check that Volatility 3 and model files are available."""
    # Check Volatility
    try:
        vol_cmd = check_volatility(vol_path)
        console.print(f"[green]Volatility 3:[/green] {vol_cmd}")
    except RuntimeError:
        console.print(f"[red]Volatility 3:[/red] not found at '{vol_path}'")

    # Check models
    try:
        load_pipeline(model_dir)
        console.print("[green]Model files:[/green] all present")
    except FileNotFoundError as e:
        console.print(f"[red]Model files:[/red] {e}")


def _display_result(result: dict, explanation: dict = None):
    """Display prediction result as a rich panel."""
    # Warning disclaimer
    console.print(
        "\n[yellow]⚠️  Warning: This classifier is not 100% accurate. "
        "Results may contain false positives/negatives. "
        "Use as a triage tool only, not for final determination.[/yellow]\n"
    )

    is_malware = result["label"] == "Malware"
    color = "red" if is_malware else "green"
    confidence_pct = f"{result['confidence'] * 100:.1f}%"

    # Verdict panel
    if is_malware:
        subtype = result["subtype"]
        sub_conf = f"{result['subtype_confidence'] * 100:.1f}%"
        verdict = f"[bold {color}]MALWARE DETECTED[/bold {color}]"
        details = f"Type: [bold]{subtype}[/bold] ({sub_conf} confidence)\n"
        details += f"Malware confidence: {confidence_pct}"

        # Subtype probabilities
        if result["subtype_probabilities"]:
            details += "\n\nSubtype probabilities:"
            for name, prob in sorted(
                result["subtype_probabilities"].items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                bar_len = int(prob * 30)
                bar = "\u2588" * bar_len + "\u2591" * (30 - bar_len)
                details += f"\n  {name:<12} {bar} {prob*100:.1f}%"
    else:
        verdict = f"[bold {color}]BENIGN[/bold {color}]"
        details = f"Confidence: {confidence_pct}"

    console.print(
        Panel(f"{verdict}\n\n{details}", title="memhuntr", border_style=color)
    )

    # Explanation table
    if explanation:
        for stage_key, label in [
            ("stage1_top", "Binary (Benign vs Malware)"),
            ("stage2_top", "Subtype Classification"),
        ]:
            if stage_key not in explanation:
                continue
            table = Table(title=f"Top Features \u2014 {label}")
            table.add_column("Feature", style="cyan")
            table.add_column("Importance", justify="right")

            for feat, imp in explanation[stage_key].items():
                table.add_row(feat, f"{imp*100:.1f}%")

            console.print(table)


def main():
    app()


if __name__ == "__main__":
    main()
