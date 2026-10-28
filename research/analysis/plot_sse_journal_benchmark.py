#!/usr/bin/env python3
"""Render the persistent SSE journal benchmark summary as a dependency-free SVG."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

try:
    from research.analysis.verify_sse_journal_benchmark import verify_report
except ModuleNotFoundError as error:
    if error.name != "research":
        raise
    from verify_sse_journal_benchmark import verify_report


WIDTH = 1000
HEIGHT = 900
LEFT = 125
RIGHT = 955
PLOT_WIDTH = RIGHT - LEFT
PANEL_HEIGHT = 232
PANEL_TOPS = (100, 350, 600)


def _text(x: float, y: float, content: str, *, size: int = 14, weight: str = "normal", anchor: str = "start") -> str:
    escaped = html.escape(content)
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="sans-serif" '
        f'font-size="{size}px" font-weight="{weight}" text-anchor="{anchor}" fill="#182230">'
        f"{escaped}</text>"
    )


def render_svg(report: dict[str, Any]) -> str:
    """Render a three-panel SVG from a verified report summary."""
    summaries = report.get("summary")
    if not isinstance(summaries, list) or not summaries:
        raise ValueError("report has no summary rows")
    if any("mean_bootstrap_ci95" not in row.get("index_build_ns", {}) for row in summaries):
        raise ValueError("report summary does not contain bootstrap intervals")

    panels = (
        ("Journal byte amplification", "journal_byte_amplification", 1.0, "×", 270.0),
        ("Index build time", "index_build_ns", 1e9, "seconds", 280.0),
        ("Fresh-process recovery", "recovery_open_trial_median_ns", 1e6, "milliseconds", 35.0),
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-labelledby="title description">',
        '<title id="title">Persistent SSE journal scaling benchmark</title>',
        '<desc id="description">Journal-byte amplification, index-build time, and fresh-process recovery time for four index sizes. Error bars are 95 percent trial-level bootstrap confidence intervals.</desc>',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        _text(LEFT, 36, "Persistent SSE journal scaling", size=24, weight="bold"),
        _text(LEFT, 61, "30 independent trials per index size; points show means and bars show 95% bootstrap CIs", size=14),
        _text(LEFT, 82, "Journal-byte amplification counts application journal frames, not SQLite, filesystem, or physical-device writes.", size=12),
    ]

    for panel_index, (title, metric, divisor, unit, y_max) in enumerate(panels):
        top = PANEL_TOPS[panel_index]
        plot_top = top + 38
        plot_bottom = top + PANEL_HEIGHT - 35
        plot_height = plot_bottom - plot_top
        parts.append(_text(LEFT, top + 20, title, size=18, weight="bold"))
        parts.append(f'<line x1="{LEFT}" y1="{plot_top}" x2="{LEFT}" y2="{plot_bottom}" stroke="#344054" stroke-width="1.2"/>')
        parts.append(f'<line x1="{LEFT}" y1="{plot_bottom}" x2="{RIGHT}" y2="{plot_bottom}" stroke="#344054" stroke-width="1.2"/>')
        for tick in range(5):
            value = y_max * tick / 4
            y = plot_bottom - plot_height * tick / 4
            parts.append(f'<line x1="{LEFT}" y1="{y:.1f}" x2="{RIGHT}" y2="{y:.1f}" stroke="#e4e7ec" stroke-width="1"/>')
            label = f"{value:.0f}" if y_max >= 100 else f"{value:.1f}"
            parts.append(_text(LEFT - 12, y + 5, label, size=12, anchor="end"))

        count = len(summaries)
        points = []
        for index, row in enumerate(summaries):
            x = LEFT + PLOT_WIDTH * (index + 0.5) / count
            stats = row[metric]
            mean = float(stats["mean"]) / divisor
            low, high = (float(value) / divisor for value in stats["mean_bootstrap_ci95"])
            y = plot_bottom - (mean / y_max) * plot_height
            y_low = plot_bottom - (low / y_max) * plot_height
            y_high = plot_bottom - (high / y_max) * plot_height
            points.append((x, y))
            parts.append(f'<line x1="{x:.1f}" y1="{y_low:.1f}" x2="{x:.1f}" y2="{y_high:.1f}" stroke="#175cd3" stroke-width="2"/>')
            parts.append(f'<line x1="{x - 7:.1f}" y1="{y_low:.1f}" x2="{x + 7:.1f}" y2="{y_low:.1f}" stroke="#175cd3" stroke-width="2"/>')
            parts.append(f'<line x1="{x - 7:.1f}" y1="{y_high:.1f}" x2="{x + 7:.1f}" y2="{y_high:.1f}" stroke="#175cd3" stroke-width="2"/>')
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="#175cd3"/>')
            parts.append(_text(x, plot_bottom + 20, str(row["index_size"]), size=12, anchor="middle"))

        if len(points) > 1:
            coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
            parts.append(f'<polyline points="{coordinates}" fill="none" stroke="#175cd3" stroke-width="1.5" opacity="0.75"/>')
            for x, y in points:
                parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="#175cd3"/>')

        parts.append(_text((LEFT + RIGHT) / 2, plot_bottom + 34, "postings per index", size=12, anchor="middle"))
        parts.append(
            f'<text x="25" y="{(plot_top + plot_bottom) / 2:.1f}" transform="rotate(-90 25 {(plot_top + plot_bottom) / 2:.1f})" '
            f'font-family="sans-serif" font-size="12px" text-anchor="middle" fill="#182230">{html.escape(unit)}</text>'
        )

    seed = report.get("configuration", {}).get("schedule_seed", "unknown")
    revision = report.get("source_revision", "unknown")
    parts.append(_text(LEFT, 866, f"Schedule seed: {seed}    Source revision: {revision}", size=11))
    parts.append(_text(LEFT, 884, "Recovery: mean of each trial's median across five nested fresh-process opens; file cache was not flushed.", size=11))
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path, help="destination SVG path")
    parser.add_argument("--expected-revision")
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    config = json.loads(args.config.read_text(encoding="utf-8"))
    verify_report(report, config, args.expected_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_svg(report), encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
