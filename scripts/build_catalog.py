#!/usr/bin/env python3
"""Build an OSCAL Catalog JSON from the CNCF controls-catalog YAML source files.

Usage:
    python scripts/build_catalog.py [--download-dir DOWNLOAD_DIR] [--trestle-ws TRESTLE_WS]

Defaults:
    --download-dir  download/
    --trestle-ws    trestle.ws

Output is written to <trestle-ws>/catalogs/cncf-controls/catalog.json
"""

import argparse
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import catalog as cat
from trestle.oscal import common


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(text: str) -> str:
    """Convert a group title to a valid OSCAL XML-NCName token (used as id)."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text.strip()).strip("-").lower()
    # NCName must start with a letter or underscore
    if slug and slug[0].isdigit():
        slug = "g-" + slug
    return slug or "group"


def _load_yaml(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_metadata_yaml(download_dir: Path) -> dict:
    return _load_yaml(download_dir / "metadata.yaml")


def load_groups(download_dir: Path) -> list[dict]:
    data = _load_yaml(download_dir / "groups.yaml")
    return data.get("groups", [])


def load_all_guidelines(download_dir: Path) -> list[dict]:
    """Load every guideline from every per-group YAML file."""
    group_files = [
        "access.yaml",
        "compute.yaml",
        "deploy.yaml",
        "develop.yaml",
        "distribute.yaml",
        "securing-artefacts.yaml",
        "securing-build-pipelines.yaml",
        "securing-materials.yaml",
        "securing-the-source-code.yaml",
        "security-assurance.yaml",
        "storage.yaml",
    ]
    guidelines: list[dict] = []
    for fname in group_files:
        data = _load_yaml(download_dir / fname)
        guidelines.extend(data.get("guidelines", []))
    return guidelines


def load_nist_mapping(download_dir: Path) -> dict[str, list[dict]]:
    """Return {cnsc_id: [{entry-id, rationale}, ...]} from the mapping file."""
    data = _load_yaml(download_dir / "cnsc-nist-800-53-mapping.yaml")
    result: dict[str, list[dict]] = {}
    for entry in data.get("mappings", []):
        src = entry.get("source", "")
        result[src] = entry.get("targets", [])
    return result


# ---------------------------------------------------------------------------
# OSCAL builders
# ---------------------------------------------------------------------------

def build_control(guideline: dict, nist_map: dict[str, list[dict]]) -> cat.Control:
    """Convert a single CNSC guideline dict into an OSCAL Control."""
    ctrl_id = guideline["id"]

    parts: list[common.Part] = []

    # statement part — the objective text
    parts.append(
        common.Part(
            id=f"{ctrl_id}_smt",
            name="statement",
            prose=guideline.get("objective", ""),
        )
    )

    # guidance part — the recommendations text (optional)
    recs = guideline.get("recommendations")
    if recs:
        parts.append(
            common.Part(
                id=f"{ctrl_id}_gdn",
                name="guidance",
                prose=recs if isinstance(recs, str) else "\n".join(recs),
            )
        )

    # props — applicability groups
    props: list[common.Property] = []
    for app in guideline.get("applicability", []):
        props.append(
            common.Property(name="applicability", value=app)
        )

    # links — see-also references
    links: list[common.Link] = []
    for ref in guideline.get("see-also", []):
        links.append(common.Link(href=f"#{ref}", rel="related"))

    # links — NIST 800-53 mappings
    for target in nist_map.get(ctrl_id, []):
        nist_id = target.get("entry-id", "")
        rationale = target.get("rationale", "")
        # Encode the NIST control ID as an href using the canonical NIST URI
        href = (
            f"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
            f"#{nist_id}"
        )
        links.append(
            common.Link(href=href, rel="related", text=nist_id)
        )
        if rationale:
            parts.append(
                common.Part(
                    id=f"{ctrl_id}_nist_{re.sub(r'[^A-Za-z0-9]', '_', nist_id)}",
                    name="mapping-rationale",
                    title=nist_id,
                    prose=rationale,
                )
            )

    return cat.Control(
        id=ctrl_id,
        title=guideline.get("title", ctrl_id),
        parts=parts or None,
        props=props or None,
        links=links or None,
    )


def build_catalog(download_dir: Path) -> cat.Catalog:
    meta_src = load_metadata_yaml(download_dir)
    groups_src = load_groups(download_dir)
    guidelines = load_all_guidelines(download_dir)
    nist_map = load_nist_mapping(download_dir)

    # Index guidelines by group name
    by_group: dict[str, list[dict]] = {}
    for g in guidelines:
        group_name = g.get("group", "Ungrouped")
        by_group.setdefault(group_name, []).append(g)

    # Build OSCAL groups preserving the order from groups.yaml
    oscal_groups: list[cat.Group2] = []
    for grp in groups_src:
        group_title = grp["title"]
        group_name = grp["id"]  # matches "group:" field in guidelines
        slug = _slugify(group_title)

        controls = [
            build_control(gl, nist_map)
            for gl in by_group.get(group_name, [])
        ]

        oscal_groups.append(
            cat.Group2(
                id=slug,
                title=group_title,
                parts=[common.Part(name="overview", prose=grp.get("description", ""))],
                controls=controls or None,
            )
        )

    # Build metadata
    src_meta = meta_src.get("metadata", {})
    version = str(src_meta.get("version", "1.0"))
    author_name = src_meta.get("author", {}).get("name", "CNCF TAG Security and Compliance")
    author_id = src_meta.get("author", {}).get("id", "tag-sc")

    party_uuid = str(uuid.uuid4())
    metadata = common.Metadata(
        title=meta_src.get("title", "Cloud Native Security Controls Catalog"),
        **{"last-modified": datetime.now(tz=timezone.utc)},
        version=version,
        **{"oscal-version": OSCAL_VERSION},
        roles=[
            common.Role(id="creator", title="Creator"),
        ],
        parties=[
            common.Parties(
                uuid=party_uuid,
                type="organization",
                name=author_name,
            )
        ],
        responsible_parties=[
            common.ResponsibleParty(
                **{"role-id": "creator"},
                **{"party-uuids": [party_uuid]},
            )
        ],
    )

    return cat.Catalog(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        groups=oscal_groups,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--download-dir",
        default="download",
        help="Directory containing the CNCF YAML source files (default: download/)",
    )
    parser.add_argument(
        "--trestle-ws",
        default="trestle.ws",
        help="Path to the trestle workspace root (default: trestle.ws)",
    )
    args = parser.parse_args()

    download_dir = Path(args.download_dir)
    output_path = Path(args.trestle_ws) / "catalogs" / "cncf-controls" / "catalog.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    catalog = build_catalog(download_dir)

    model = cat.Model(catalog=catalog)
    output_path.write_text(
        model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )
    print(f"Written: {output_path}")


if __name__ == "__main__":
    main()
