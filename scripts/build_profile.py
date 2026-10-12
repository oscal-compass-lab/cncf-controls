#!/usr/bin/env python3
"""Build the generic cncf-repo OSCAL Profile.

The cncf-repo profile selects the subset of CNCF controls that apply to ANY
source code repository — regardless of what the repo does.  Controls that are
purely runtime, infrastructure, or deployment pipeline concerns are excluded.

The profile imports the cncf-controls catalog and explicitly selects only the
source-repo-applicable controls using OSCAL include-controls.

Usage:
    python scripts/build_profile.py [--catalog-path CATALOG_PATH]
                                    [--trestle-ws TRESTLE_WS]

Defaults:
    --catalog-path  trestle.ws/catalogs/cncf-controls/catalog.json
    --trestle-ws    trestle.ws

Output:
    trestle.ws/profiles/cncf-repo/profile.json
"""

import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import profile as prof
from trestle.oscal import common


# ---------------------------------------------------------------------------
# Control selection
#
# These are the controls that CAN apply to a source code repository.
# Grouped by rationale so the list is easy to maintain.
# ---------------------------------------------------------------------------

# Develop — testing, scanning, code review, environment practices
DEVELOP = [
    "CNSC-65",   # Early Vulnerability Scanning — IDE/PR scanning
    "CNSC-67",   # Business-Critical Code Testing
    "CNSC-68",   # Infrastructure Testing
    "CNSC-69",   # Local Test Execution
    "CNSC-71",   # Code Review Requirements (2 reviewers)
    "CNSC-72",   # Code Quality
    "CNSC-73",   # Full Infrastructure Testing
    "CNSC-74",   # Regression Testing
    "CNSC-75",   # Security Regression Testing
    "CNSC-78",   # Threat-Informed Test Development
    "CNSC-195",  # Secure Configuration Defaults
    "CNSC-259",  # Early Vulnerability Scanning (CI integration)
    "CNSC-265",  # Code Review Requirements (at least 1 reviewer)
]

# Distribute — pipeline-level checks applicable to a repo
DISTRIBUTE = [
    "CNSC-82",   # Static Application Security Testing (SAST)
    "CNSC-85",   # Manifest/artifact scanning in CI pipeline
]

# Securing Build Pipelines — pipeline-as-code and reproducibility
SECURING_BUILD_PIPELINES = [
    "CNSC-150",  # Environment and Dependency Validation
    "CNSC-152",  # Reproducible Builds (lock file)
    "CNSC-153",  # External Requirement Verification (hash pinning)
    "CNSC-154",  # Build Determinism
    "CNSC-155",  # Build Environment Recording
    "CNSC-156",  # Build Environment Automation
    "CNSC-158",  # Pipeline as Code
    "CNSC-159",  # Pipeline Standardization
    "CNSC-165",  # Secured Output Storage
    "CNSC-166",  # Pipeline Modification Control
    "CNSC-167",  # User Role Definition
    "CNSC-168",  # Root of Trust Establishment
]

# Securing Materials — dependency and supply chain hygiene
SECURING_MATERIALS = [
    "CNSC-173",  # Third-Party Artifact Verification
    "CNSC-174",  # Third-Party SBOM Requirements
    "CNSC-175",  # Dependency Tracking
    "CNSC-177",  # Trusted Package Sources
    "CNSC-178",  # Immutable SBOM Generation
    "CNSC-179",  # Software Vulnerability Scanning
    "CNSC-180",  # License Compliance Scanning
    "CNSC-181",  # Software Composition Analysis
]

# Securing the Source Code — all controls apply to any repo
SECURING_SOURCE_CODE = [
    "CNSC-182",  # Commit and Tag Signing
    "CNSC-183",  # Branch Protection Attestation
    "CNSC-184",  # Secret Commit Prevention
    "CNSC-185",  # Repository Access Definition
    "CNSC-186",  # Automated Security Scanning
    "CNSC-187",  # Contribution Policy Enforcement
    "CNSC-188",  # Functional Role Definition
    "CNSC-189",  # Four-Eyes Principle
    "CNSC-190",  # Branch Protection Rules
    "CNSC-191",  # Repository MFA Enforcement
    "CNSC-192",  # SSH Key Access
    "CNSC-193",  # Key Rotation Policy
    "CNSC-194",  # Ephemeral Credentials
]

# Security Assurance — GitOps, supply chain, identity practices
SECURITY_ASSURANCE = [
    "CNSC-121",  # Threat Modeling
    "CNSC-196",  # Supply Chain Security Best Practices
    "CNSC-197",  # Repository and Branch Access Control
    "CNSC-198",  # Git Secret Prevention
    "CNSC-199",  # Commit Identity Enforcement
    "CNSC-200",  # Linear History Enforcement
    "CNSC-201",  # Branching Policy Enforcement
    "CNSC-202",  # Git Tool Security Monitoring
    "CNSC-203",  # Repository Credential Management
    "CNSC-204",  # Technical Account Management
    "CNSC-205",  # Privilege Escalation Prevention
]

# Full ordered list of selected control IDs
SELECTED_CONTROLS = (
    DEVELOP
    + DISTRIBUTE
    + SECURING_BUILD_PIPELINES
    + SECURING_MATERIALS
    + SECURING_SOURCE_CODE
    + SECURITY_ASSURANCE
)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_profile(catalog_path: Path, trestle_ws: Path) -> prof.Model:
    now = datetime.now(tz=timezone.utc)

    # Relative href from the profile location to the catalog
    # trestle resolves internal hrefs as trestle://catalogs/<name>/catalog.json
    catalog_href = "trestle://catalogs/cncf-controls/catalog.json"

    metadata = common.Metadata(
        title="CNCF Source Repository Profile",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
        props=[
            common.Property(
                name="description",
                value=(
                    "Generic profile selecting CNCF controls applicable to any source "
                    "code repository. Excludes runtime, infrastructure, and deployment "
                    "pipeline controls that cannot be assessed at the repo level."
                ),
            )
        ],
        parties=[
            common.Parties(
                uuid=str(uuid.uuid4()),
                type="organization",
                name="CNCF TAG Security and Compliance",
            )
        ],
    )

    # Import the catalog and include only the selected controls
    imports = [
        prof.Import2(
            href=catalog_href,
            **{
                "include-controls": [
                    prof.SelectControl(**{"with-ids": [ctrl_id]})
                    for ctrl_id in SELECTED_CONTROLS
                ]
            },
        )
    ]

    profile = prof.Profile(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        imports=imports,
    )

    return prof.Model(profile=profile)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog-path",
        default="trestle.ws/catalogs/cncf-controls/catalog.json",
        help="Path to the OSCAL catalog JSON",
    )
    parser.add_argument(
        "--trestle-ws",
        default="trestle.ws",
        help="Path to the trestle workspace root (default: trestle.ws)",
    )
    args = parser.parse_args()

    trestle_ws   = Path(args.trestle_ws)
    catalog_path = Path(args.catalog_path)

    model = build_profile(catalog_path, trestle_ws)

    out_dir  = trestle_ws / "profiles" / "cncf-repo"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "profile.json"
    out_path.write_text(
        model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )

    print(f"Written: {out_path}  ({len(SELECTED_CONTROLS)} controls selected)")


if __name__ == "__main__":
    main()
