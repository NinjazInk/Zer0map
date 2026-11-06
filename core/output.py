"""Console output helpers: themed colors, tables, status styling and result export.

Only the terminal's standard ANSI palette (red/yellow/green/cyan/magenta + bold/dim)
is used, so output stays readable on both dark and light terminal themes.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

THEME = Theme(
    {
        "critical": "bold red",
        "fail": "bold red",
        "warning": "yellow",
        "pass": "green",
        "info": "cyan",
        "muted": "dim",
        "accent": "bold magenta",
        "heading": "bold",
        "option": "bold cyan",
    }
)

console = Console(theme=THEME, highlight=False)

# Map status / severity / confidence labels to theme styles.
STATUS_STYLES = {
    "PASS": "pass",
    "OK": "pass",
    "PRESENT": "pass",
    "OPEN": "pass",
    "WARN": "warning",
    "WARNING": "warning",
    "MISCONFIGURED": "warning",
    "FAIL": "critical",
    "MISSING": "critical",
    "CRITICAL": "critical",
    "HIGH": "critical",
    "MEDIUM": "warning",
    "LOW": "info",
    "INFO": "info",
}


def style_for(label: str) -> str:
    return STATUS_STYLES.get(str(label).upper(), "")


def status_text(label: str) -> Text:
    """A status/severity label rendered in its color."""
    return Text(str(label), style=style_for(label))


# ----------------------------------------------------------------------------- printing
def _emit(prefix: str, style: str, msg: Any) -> None:
    line = Text()
    line.append(prefix, style=style)
    line.append(" ")
    line.append(msg if isinstance(msg, Text) else Text(str(msg)))
    console.print(line)


def print_info(msg: Any) -> None:
    _emit("[*]", "info", msg)


def print_good(msg: Any) -> None:
    _emit("[+]", "pass", msg)


def print_warn(msg: Any) -> None:
    _emit("[!]", "warning", msg)


def print_error(msg: Any) -> None:
    _emit("[-]", "critical", msg)


def print_critical(msg: Any) -> None:
    _emit("[!!]", "critical", msg)


def print_section(title: str) -> None:
    console.print()
    console.rule(Text(title, style="heading"), align="left", style="muted")


# ----------------------------------------------------------------------------- tables
def make_table(title: str | None, columns: Iterable[str | tuple[str, dict]]) -> Table:
    """Create a consistently styled table. Columns are names or (name, column_kwargs)."""
    table = Table(
        title=title,
        title_style="heading",
        title_justify="left",
        box=box.SIMPLE_HEAVY,
        header_style="bold",
        show_lines=False,
        expand=False,
    )
    for col in columns:
        if isinstance(col, tuple):
            table.add_column(col[0], **col[1])
        else:
            table.add_column(col)
    return table


def add_row(table: Table, *values: Any, style: str | None = None) -> None:
    """Add a row, treating plain strings as literal text (no markup injection from target data)."""
    cells = [v if isinstance(v, Text) else Text("" if v is None else str(v)) for v in values]
    table.add_row(*cells, style=style)


# ----------------------------------------------------------------------------- export
def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _title(key: str) -> str:
    return str(key).replace("_", " ").title()


def _md_render(obj: Any, level: int, out: list[str]) -> None:
    if isinstance(obj, dict):
        scalars = {k: v for k, v in obj.items() if _is_scalar(v)}
        nested = {k: v for k, v in obj.items() if not _is_scalar(v)}
        for k, v in scalars.items():
            out.append(f"- **{_title(k)}**: {_md_escape(v)}")
        if scalars:
            out.append("")
        for k, v in nested.items():
            out.append(f"{'#' * min(level, 6)} {_title(k)}")
            out.append("")
            _md_render(v, level + 1, out)
    elif isinstance(obj, (list, tuple)):
        if not obj:
            out.append("_None_")
            out.append("")
        elif all(isinstance(i, dict) for i in obj):
            keys: list[str] = []
            for item in obj:
                for k in item:
                    if k not in keys:
                        keys.append(k)
            out.append("| " + " | ".join(_title(k) for k in keys) + " |")
            out.append("|" + "---|" * len(keys))
            for item in obj:
                row = []
                for k in keys:
                    v = item.get(k, "")
                    if isinstance(v, (list, tuple)):
                        v = ", ".join(str(x) for x in v)
                    elif isinstance(v, dict):
                        v = json.dumps(v, default=str)
                    row.append(_md_escape("" if v is None else v))
                out.append("| " + " | ".join(row) + " |")
            out.append("")
        else:
            for item in obj:
                if _is_scalar(item):
                    out.append(f"- {_md_escape(item)}")
                else:
                    out.append(f"- `{_md_escape(json.dumps(item, default=str))}`")
            out.append("")
    else:
        out.append(_md_escape(obj))
        out.append("")


def to_markdown(record: dict) -> str:
    out = [
        f"# Zer0map Report: {record.get('module', 'unknown')}",
        "",
        f"- **Generated**: {record.get('timestamp', '')}",
        f"- **Tool**: Zer0map v{record.get('version', '')}",
        "",
        "## Options",
        "",
    ]
    _md_render(record.get("options", {}), 3, out)
    out.append("## Results")
    out.append("")
    _md_render(record.get("results", {}), 3, out)
    out.append("---")
    out.append("_For authorized testing and educational purposes only._")
    return "\n".join(out) + "\n"


def export_results(record: dict, filename: str) -> Path:
    """Write a result record to .json or .md. Raises ValueError/OSError on failure."""
    path = Path(filename).expanduser()
    ext = path.suffix.lower()
    if ext == ".json":
        content = json.dumps(record, indent=2, default=str)
    elif ext in (".md", ".markdown"):
        content = to_markdown(record)
    else:
        raise ValueError("Unsupported export format. Use a .json or .md filename.")
    path.write_text(content, encoding="utf-8")
    return path.resolve()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
