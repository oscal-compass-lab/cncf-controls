#!/usr/bin/env python3
"""Regenerate the chart PNG and controls table in README.md from the OSCAL catalog.

Usage:
    python scripts/update_readme.py [--catalog CATALOG] [--readme README]

Defaults:
    --catalog  trestle.ws/catalogs/cncf-controls/catalog.json
    --readme   README.md

The script:
  1. Generates docs/catalog-chart.png — a colored horizontal bar chart.
  2. Rewrites the content between the sentinel comment pairs in README.md:
       <!-- chart-start --> ... <!-- chart-end -->
       <!-- table-start --> ... <!-- table-end -->
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend, no display needed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

CHART_START = "<!-- chart-start -->"
CHART_END   = "<!-- chart-end -->"
TABLE_START = "<!-- table-start -->"
TABLE_END   = "<!-- table-end -->"

CHART_PATH  = "docs/catalog-chart.png"

# Colour palette — one per group (cycles if more groups than colours)
COLOURS = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
    "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
    "#aec7e8",
]


def load_groups(catalog_path: Path) -> list[dict]:
    """Return [{title, controls: [id, ...]}, ...] from the catalog."""
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    groups = []
    for g in data["catalog"]["groups"]:
        groups.append({
            "title": g["title"],
            "controls": [c["id"] for c in g.get("controls", [])],
        })
    return groups


def generate_chart(groups: list[dict], chart_path: Path) -> None:
    """Render a horizontal bar chart and save it as a PNG."""
    titles = [g["title"] for g in groups]
    counts = [len(g["controls"]) for g in groups]
    colours = [COLOURS[i % len(COLOURS)] for i in range(len(groups))]

    # Reverse so the first group appears at the top
    titles  = titles[::-1]
    counts  = counts[::-1]
    colours = colours[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(titles, counts, color=colours, edgecolor="white", height=0.6)

    # Value labels at the end of each bar
    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.4,
            bar.get_y() + bar.get_height() / 2,
            str(count),
            va="center",
            ha="left",
            fontsize=9,
            color="#333333",
        )

    ax.set_xlabel("Number of Controls", fontsize=10)
    ax.set_title("CNCF Controls Catalog — Controls per Group", fontsize=12, fontweight="bold", pad=14)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_xlim(0, max(counts) + 6)
    ax.tick_params(axis="y", labelsize=9)
    ax.tick_params(axis="x", labelsize=9)

    fig.tight_layout()
    chart_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {chart_path}")


def build_chart_md(chart_path: Path, readme_path: Path) -> str:
    """Return the markdown image tag using a path relative to the README."""
    rel = chart_path.relative_to(readme_path.parent) if chart_path.is_relative_to(readme_path.parent) else chart_path
    return f"![Controls per Group]({rel})"


def build_table(groups: list[dict]) -> str:
    total = sum(len(g["controls"]) for g in groups)
    rows = []
    rows.append("| Group | Count | Controls |")
    rows.append("|---|:---:|---|")
    for g in groups:
        ctrl_ids = ", ".join(g["controls"])
        rows.append(f"| {g['title']} | {len(g['controls'])} | {ctrl_ids} |")
    rows.append(f"| **Total** | **{total}** | |")
    return "\n".join(rows)


def replace_section(text: str, start_marker: str, end_marker: str, new_content: str) -> str:
    start_idx = text.find(start_marker)
    end_idx   = text.find(end_marker)
    if start_idx == -1 or end_idx == -1:
        raise ValueError(f"Markers not found in README: '{start_marker}' / '{end_marker}'")
    before = text[:start_idx + len(start_marker)]
    after  = text[end_idx:]
    return before + "\n\n" + new_content + "\n\n" + after


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        default="trestle.ws/catalogs/cncf-controls/catalog.json",
        help="Path to the OSCAL catalog JSON",
    )
    parser.add_argument(
        "--readme",
        default="README.md",
        help="Path to README.md",
    )
    args = parser.parse_args()

    catalog_path = Path(args.catalog)
    readme_path  = Path(args.readme)
    chart_path   = Path(CHART_PATH)

    groups = load_groups(catalog_path)

    generate_chart(groups, chart_path)

    text = readme_path.read_text(encoding="utf-8")
    text = replace_section(text, CHART_START, CHART_END, build_chart_md(chart_path, readme_path))
    text = replace_section(text, TABLE_START, TABLE_END, build_table(groups))
    readme_path.write_text(text, encoding="utf-8")

    total = sum(len(g["controls"]) for g in groups)
    print(f"Updated: {readme_path}  ({len(groups)} groups, {total} controls)")


if __name__ == "__main__":
    main()
