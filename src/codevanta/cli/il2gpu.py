"""IL2CPP and GPU code-object commands (pure-Python structural depth)."""

from __future__ import annotations

from typing import Annotated

import typer

from codevanta.analysis.gpu_meta import inspect_gpu
from codevanta.analysis.il2cpp_meta import parse_il2cpp_meta

app = typer.Typer(help="IL2CPP metadata and GPU code-object inspection")


def _emit(payload: dict, output_format: str, table_rows: list[tuple[str, str]]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    if output_format == "json":
        import json

        console.print_json(json.dumps(payload, indent=2))
        return
    table = Table(title="IL2CPP / GPU")
    table.add_column("Field")
    table.add_column("Value")
    for key, value in table_rows:
        table.add_row(key, value)
    for key, value in payload.items():
        if not isinstance(value, (list, dict)):
            table.add_row(str(key), str(value))
    console.print(table)


@app.command("il2cpp")
def il2cpp_cmd(
    path: Annotated[str, typer.Argument(help="Path to global-metadata.dat")],
    output_format: Annotated[str, typer.Option("--format", help="text or json")] = "text",
) -> None:
    """Parse the global-metadata header-pair structure (structure only)."""
    summary = parse_il2cpp_meta(path).to_dict()
    rows = [(t["name"], f"off={t['offset']} size={t['size']}") for t in summary["tables"]]
    _emit(summary, output_format, rows)


@app.command("gpu")
def gpu_cmd(
    path: Annotated[str, typer.Argument(help="Path to a fatbin/cubin/COB container")],
    output_format: Annotated[str, typer.Option("--format", help="text or json")] = "text",
) -> None:
    """Inspect a CUDA fatbin, CUBIN, or Clang offload bundle."""
    summary = inspect_gpu(path).to_dict()
    rows = [(e["kind"], f"off={e['offset']} size={e['size']} arch={e['arch']}") for e in summary["entries"]]
    _emit(summary, output_format, rows)
