#!/usr/bin/env python3
"""Regenerate the Mermaid chart and controls table in README.md from the OSCAL catalog.

Usage:
    python scripts/update_readme.py [--catalog CATALOG] [--readme README]

Defaults:
    --catalog  trestle.ws/catalogs/cncf-controls/catalog.json
    --readme   README.md

The script rewrites the content between the sentinel comment pairs:
    <!-- chart-start --> ... <!-- chart-end -->
    <!-- table-start --> ... <!-- table-end -->
"""

import argparse
import json
from pathlib import Path

CHART_START = "<!-- chart-start -->"
CHART_END   = "<!-- chart-end -->"
TABLE_START = "<!-- table-start -->"
TABLE_END   = "<!-- table-end -->"


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


def build_chart(groups: list[dict]) -> str:
    titles = [g["title"] for g in groups]
    counts = [len(g["controls"]) for g in groups]
    max_count = max(counts)
    # round up to next multiple of 5 for a clean y-axis ceiling
    ceiling = max_count + (5 - max_count % 5) % 5

    x_items = "\n".join(f'        "{t}"' for t in titles)
    bars = ", ".join(str(c) for c in counts)

    return (
        "```mermaid\n"
        "xychart-beta horizontal\n"
        '    title "Controls per Group"\n'
        "    x-axis [\n"
        f"{x_items}\n"
        "    ]\n"
        f'    y-axis "Controls" 0 --> {ceiling}\n'
        f"    bar [{bars}]\n"
        "```"
    )


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

    groups = load_groups(catalog_path)

    text = readme_path.read_text(encoding="utf-8")
    text = replace_section(text, CHART_START, CHART_END, build_chart(groups))
    text = replace_section(text, TABLE_START, TABLE_END, build_table(groups))
    readme_path.write_text(text, encoding="utf-8")

    total = sum(len(g["controls"]) for g in groups)
    print(f"Updated: {readme_path}  ({len(groups)} groups, {total} controls)")


if __name__ == "__main__":
    main()
