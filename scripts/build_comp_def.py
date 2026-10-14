#!/usr/bin/env python3
"""Build the shared cncf-repo OSCAL Component Definition.

Defines a single component — "CNCF Source Repository" — with rules, checks,
and default parameter values for every control selected by the cncf-repo
profile.  This component definition is shared across all CNCF source repos.
A per-repo overlay only needs to override the parameters that differ from
the defaults declared here.

Usage:
    python scripts/build_comp_def.py [--trestle-ws TRESTLE_WS]

Defaults:
    --trestle-ws    trestle.ws

Output:
    trestle.ws/component-definitions/cncf-repo/component-definition.json
"""

import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import component as comp
from trestle.oscal import common


# ---------------------------------------------------------------------------
# Rule + check + parameter catalogue
#
# Each entry defines:
#   control_id   : matches the catalog/profile control ID
#   rule         : normative statement — what must be true (same for all repos)
#   check        : how to verify it — check type + parameter names referenced
#   params       : list of {id, default, description} for this control
# ---------------------------------------------------------------------------

REQUIREMENTS = [

    # -----------------------------------------------------------------------
    # Develop
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-65",
        "rule": "Vulnerability and configuration scanning must be integrated at the pull-request or CI stage.",
        "check": "makefile-target | param: pipeline-vuln-scan-target",
        "params": [
            {"id": "pipeline-vuln-scan-target", "default": "audit-deps",
             "description": "Makefile/pipeline target that runs vulnerability scanning."},
        ],
    },
    {
        "control_id": "CNSC-67",
        "rule": "Tests must exist for business-critical code paths.",
        "check": "file-exists | param: test-dir",
        "params": [
            {"id": "test-dir", "default": "tests",
             "description": "Directory containing test suites."},
        ],
    },
    {
        "control_id": "CNSC-68",
        "rule": "Tests must exist for business-critical infrastructure.",
        "check": "file-exists | param: test-dir",
        "params": [
            {"id": "test-dir", "default": "tests",
             "description": "Directory containing infrastructure test suites."},
        ],
    },
    {
        "control_id": "CNSC-69",
        "rule": "Test suites must be runnable locally without external dependencies.",
        "check": "makefile-target | param: test-target",
        "params": [
            {"id": "test-target", "default": "test",
             "description": "Makefile/pipeline target that runs tests locally."},
        ],
    },
    {
        "control_id": "CNSC-71",
        "rule": "At least two non-author reviewers must approve before merging.",
        "check": "git-branch-protected | param: default-branch; min-reviewers",
        "params": [
            {"id": "default-branch", "default": "main",
             "description": "The repository default branch name."},
            {"id": "min-reviewers", "default": "2",
             "description": "Minimum number of required non-author reviewers."},
        ],
    },
    {
        "control_id": "CNSC-72",
        "rule": "Code must be clean and well commented.",
        "check": "file-exists | param: pipeline-file",
        "params": [
            {"id": "pipeline-file", "default": "Makefile",
             "description": "The pipeline-as-code file (Makefile, Taskfile.yml, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-73",
        "rule": "Full infrastructure tests must be present.",
        "check": "file-exists | param: test-dir",
        "params": [],
    },
    {
        "control_id": "CNSC-74",
        "rule": "Regression tests must be present.",
        "check": "file-exists | param: test-dir",
        "params": [],
    },
    {
        "control_id": "CNSC-75",
        "rule": "Test suites must be updated against new and emerging threats.",
        "check": "file-exists | param: test-dir",
        "params": [],
    },
    {
        "control_id": "CNSC-78",
        "rule": "Threat model results must be used to determine test development priorities.",
        "check": "file-exists | param: threat-model-file",
        "params": [
            {"id": "threat-model-file", "default": "THREAT_MODEL.md",
             "description": "Path to the threat model document."},
        ],
    },
    {
        "control_id": "CNSC-195",
        "rule": "Secure configuration must be the default state of the system.",
        "check": "file-exists | param: security-policy-file",
        "params": [
            {"id": "security-policy-file", "default": "SECURITY.md",
             "description": "Path to the security policy/defaults document."},
        ],
    },
    {
        "control_id": "CNSC-259",
        "rule": "Vulnerability and configuration scanning must be integrated in both the IDE and CI pipeline.",
        "check": "makefile-target | param: pipeline-vuln-scan-target",
        "params": [],
    },
    {
        "control_id": "CNSC-265",
        "rule": "At least one non-author reviewer must approve before merging.",
        "check": "git-branch-protected | param: default-branch; min-reviewers",
        "params": [],
    },

    # -----------------------------------------------------------------------
    # Distribute
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-82",
        "rule": "Static application security testing (SAST) must be performed.",
        "check": "makefile-target | param: sast-target",
        "params": [
            {"id": "sast-target", "default": "sast",
             "description": "Makefile/pipeline target that runs SAST."},
            {"id": "sast-tool", "default": "bandit",
             "description": "SAST tool (bandit, semgrep, gosec, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-85",
        "rule": "Application manifests and OSCAL artifacts must be validated in the pipeline.",
        "check": "makefile-target | param: validate-target",
        "params": [
            {"id": "validate-target", "default": "validate-catalog",
             "description": "Makefile/pipeline target that validates manifests/artifacts."},
        ],
    },

    # -----------------------------------------------------------------------
    # Securing Build Pipelines
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-150",
        "rule": "Build environments and dependencies must be validated before use.",
        "check": "file-exists | param: dependency-file",
        "params": [
            {"id": "dependency-file", "default": "requirements.txt",
             "description": "Dependency declaration file (requirements.txt, go.mod, package.json, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-152",
        "rule": "Build artifacts must be reproducible; a dependency lock file must be present.",
        "check": "file-exists | param: lock-file",
        "params": [
            {"id": "lock-file", "default": "requirements.lock",
             "description": "Dependency lock file (requirements.lock, go.sum, package-lock.json, poetry.lock, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-153",
        "rule": "External requirements must be locked and verified with hash pinning.",
        "check": "file-contains | param: pipeline-file; hash-pin-pattern",
        "params": [
            {"id": "hash-pin-pattern", "default": "--require-hashes",
             "description": "Pattern in the pipeline file that activates hash verification."},
        ],
    },
    {
        "control_id": "CNSC-154",
        "rule": "Sources of non-determinism must be eliminated; a lock file must be present.",
        "check": "file-exists | param: lock-file",
        "params": [],
    },
    {
        "control_id": "CNSC-155",
        "rule": "The build environment must be recorded.",
        "check": "file-exists | param: lock-file",
        "params": [],
    },
    {
        "control_id": "CNSC-156",
        "rule": "Creation of the build environment must be automated.",
        "check": "makefile-target | param: env-setup-target",
        "params": [
            {"id": "env-setup-target", "default": "venv",
             "description": "Makefile/pipeline target that creates the build environment."},
        ],
    },
    {
        "control_id": "CNSC-158",
        "rule": "Build and CI/CD steps must be automated through pipeline-as-code.",
        "check": "file-exists | param: pipeline-file",
        "params": [],
    },
    {
        "control_id": "CNSC-159",
        "rule": "Pipelines must be standardized across projects using a single entry point.",
        "check": "makefile-target | param: all-target",
        "params": [
            {"id": "all-target", "default": "all",
             "description": "The single top-level pipeline entry point target."},
        ],
    },
    {
        "control_id": "CNSC-165",
        "rule": "Pipeline output must be written to a separate secured storage location.",
        "check": "file-exists | param: output-artifact-path",
        "params": [
            {"id": "output-artifact-path", "default": "trestle.ws/catalogs/cncf-controls/catalog.json",
             "description": "Path to the primary secured pipeline output artifact."},
        ],
    },
    {
        "control_id": "CNSC-166",
        "rule": "Pipeline modification must only be allowed through pipeline-as-code with branch protection.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-167",
        "rule": "User roles must be defined for the repository.",
        "check": "file-exists | param: codeowners-file",
        "params": [
            {"id": "codeowners-file", "default": "CODEOWNERS",
             "description": "Path to the CODEOWNERS file (CODEOWNERS, .github/CODEOWNERS, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-168",
        "rule": "A root-of-trust establishment procedure must be documented.",
        "check": "file-exists | param: security-policy-file",
        "params": [],
    },

    # -----------------------------------------------------------------------
    # Securing Materials
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-173",
        "rule": "Third-party artifacts and open source libraries must be declared and verified.",
        "check": "file-exists | param: dependency-file",
        "params": [],
    },
    {
        "control_id": "CNSC-174",
        "rule": "An SBOM must be required from third-party suppliers.",
        "check": "file-exists | param: sbom-output-path",
        "params": [
            {"id": "sbom-output-path", "default": "sbom.json",
             "description": "Path to the generated SBOM file."},
        ],
    },
    {
        "control_id": "CNSC-175",
        "rule": "Dependencies between open source components must be tracked.",
        "check": "file-exists | param: dependency-file",
        "params": [],
    },
    {
        "control_id": "CNSC-177",
        "rule": "Only trusted package managers and repositories must be used.",
        "check": "file-contains | param: pipeline-file; trusted-registry-pattern",
        "params": [
            {"id": "trusted-registry-pattern", "default": "pip install",
             "description": "Pattern confirming use of a trusted package manager in the pipeline."},
        ],
    },
    {
        "control_id": "CNSC-178",
        "rule": "An immutable SBOM of the code must be generated.",
        "check": "makefile-target | param: sbom-target",
        "params": [
            {"id": "sbom-target", "default": "generate-sbom",
             "description": "Makefile/pipeline target that generates the SBOM."},
        ],
    },
    {
        "control_id": "CNSC-179",
        "rule": "Software must be scanned for known vulnerabilities.",
        "check": "makefile-target | param: pipeline-vuln-scan-target",
        "params": [
            {"id": "vulnerability-scanner", "default": "pip-audit",
             "description": "Vulnerability scanner tool (pip-audit, safety, trivy, grype, npm audit, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-180",
        "rule": "Software must be scanned for license compliance.",
        "check": "makefile-target | param: license-scan-target",
        "params": [
            {"id": "license-scan-target", "default": "license-check",
             "description": "Makefile/pipeline target that runs license compliance scanning."},
            {"id": "license-scanner", "default": "pip-licenses",
             "description": "License scanner tool (pip-licenses, license-checker, golicense, etc.)."},
        ],
    },
    {
        "control_id": "CNSC-181",
        "rule": "Software composition analysis must be run on ingested software.",
        "check": "makefile-target | param: sca-target",
        "params": [
            {"id": "sca-target", "default": "sca",
             "description": "Makefile/pipeline target that runs software composition analysis."},
        ],
    },

    # -----------------------------------------------------------------------
    # Securing the Source Code
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-182",
        "rule": "All commits and tags must carry a valid GPG or SSH cryptographic signature.",
        "check": "git-commits-signed | param: signed-commits-lookback",
        "params": [
            {"id": "signed-commits-lookback", "default": "10",
             "description": "Number of recent commits to verify for signatures."},
        ],
    },
    {
        "control_id": "CNSC-183",
        "rule": "Full attestation and verification must be enforced for the default branch.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-184",
        "rule": "No unencrypted secrets must be committed to the repository.",
        "check": "no-secrets-in-files | param: secrets-scan-extensions; secrets-scan-exclude-paths",
        "params": [
            {"id": "secrets-scan-extensions", "default": "py,sh,yaml,yml,env,cfg,ini",
             "description": "Comma-separated file extensions to scan for hardcoded secrets."},
            {"id": "secrets-scan-exclude-paths", "default": ".venv,trestle.ws,.git,download",
             "description": "Comma-separated directory names to exclude from secrets scanning."},
        ],
    },
    {
        "control_id": "CNSC-185",
        "rule": "Individuals or teams with write access must be explicitly defined.",
        "check": "file-exists | param: codeowners-file",
        "params": [],
    },
    {
        "control_id": "CNSC-186",
        "rule": "Software security scanning and testing must be automated in the pipeline.",
        "check": "makefile-target | param: sast-target",
        "params": [],
    },
    {
        "control_id": "CNSC-187",
        "rule": "Contribution policies must be established and documented.",
        "check": "file-exists | param: contributing-file",
        "params": [
            {"id": "contributing-file", "default": "CONTRIBUTING.md",
             "description": "Path to the contribution policy document."},
        ],
    },
    {
        "control_id": "CNSC-188",
        "rule": "Roles must be defined and aligned to functional responsibilities.",
        "check": "file-exists | param: codeowners-file",
        "params": [],
    },
    {
        "control_id": "CNSC-189",
        "rule": "An independent four-eyes principle must be enforced via branch protection.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-190",
        "rule": "Branch protection rules must be enabled on the default branch.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-191",
        "rule": "MFA must be enforced for accessing source code repositories.",
        "check": "manual | param: mfa-enforcement-scope",
        "params": [
            {"id": "mfa-enforcement-scope", "default": "organization",
             "description": "Scope at which MFA is enforced (organization, team, repository)."},
        ],
    },
    {
        "control_id": "CNSC-192",
        "rule": "SSH keys must be used to provide developer access to source code repositories.",
        "check": "file-contains | param: git-config-file; ssh-remote-pattern",
        "params": [
            {"id": "git-config-file", "default": ".git/config",
             "description": "Path to the git configuration file."},
            {"id": "ssh-remote-pattern", "default": "git@github\\.com",
             "description": "Pattern confirming SSH remote URL in git config."},
        ],
    },
    {
        "control_id": "CNSC-193",
        "rule": "A key rotation policy must be documented.",
        "check": "file-exists | param: security-policy-file",
        "params": [],
    },
    {
        "control_id": "CNSC-194",
        "rule": "Short-lived or ephemeral credentials must be used for machine and service access.",
        "check": "file-exists | param: security-policy-file",
        "params": [],
    },

    # -----------------------------------------------------------------------
    # Security Assurance
    # -----------------------------------------------------------------------
    {
        "control_id": "CNSC-121",
        "rule": "A threat model for code and infrastructure must be documented.",
        "check": "file-exists | param: threat-model-file",
        "params": [],
    },
    {
        "control_id": "CNSC-196",
        "rule": "Supply chain security best practices must be adhered to (SBOM, lock file, SCA).",
        "check": "file-exists | param: lock-file; sbom-output-path",
        "params": [],
    },
    {
        "control_id": "CNSC-197",
        "rule": "Access to repository and branches must be restricted via branch protection and CODEOWNERS.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-198",
        "rule": "Unencrypted credentials or secrets must never be stored in the repository.",
        "check": "no-secrets-in-files | param: secrets-scan-extensions; secrets-scan-exclude-paths",
        "params": [],
    },
    {
        "control_id": "CNSC-199",
        "rule": "Strong identity must be enforced with GPG-signed commits.",
        "check": "git-commits-signed | param: signed-commits-lookback",
        "params": [],
    },
    {
        "control_id": "CNSC-200",
        "rule": "Linear history must be enforced; force-push must be disallowed.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-201",
        "rule": "Branching policy must be enforced with main branch protection and code review.",
        "check": "git-branch-protected | param: default-branch",
        "params": [],
    },
    {
        "control_id": "CNSC-202",
        "rule": "Git and GitOps tools must be monitored for vulnerabilities and kept up to date.",
        "check": "manual | param: security-policy-file",
        "params": [],
    },
    {
        "control_id": "CNSC-203",
        "rule": "SSH keys and Personal Access Tokens must be rotated regularly.",
        "check": "file-exists | param: security-policy-file",
        "params": [],
    },
    {
        "control_id": "CNSC-204",
        "rule": "Dedicated non-user technical accounts must be used for automated access.",
        "check": "manual | param: security-policy-file",
        "params": [],
    },
    {
        "control_id": "CNSC-205",
        "rule": "Users who can escalate permissions must be limited to a pre-approved set.",
        "check": "manual | param: security-policy-file",
        "params": [],
    },
]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def _sp(param_id: str, value: str, remarks: str = None) -> common.SetParameter:
    return common.SetParameter(
        **{"param-id": param_id},
        values=[value],
        remarks=remarks,
    )


def build_comp_def(trestle_ws: Path) -> comp.Model:
    now = datetime.now(tz=timezone.utc)
    profile_href = "trestle://profiles/cncf-repo/profile.json"

    # Collect global default parameters (deduplicated by param id)
    global_params: dict[str, common.SetParameter] = {}
    for req in REQUIREMENTS:
        for p in req.get("params", []):
            if p["id"] not in global_params:
                global_params[p["id"]] = _sp(p["id"], p["default"], p["description"])

    # Build one ImplementedRequirement per control
    implemented = []
    for req in REQUIREMENTS:
        ctrl_id = req["control_id"]

        # props: rule and check as structured properties
        props = [
            common.Property(name="rule",  value=req["rule"]),
            common.Property(name="check", value=req["check"]),
        ]

        # set-parameters: only the params first declared on this control
        set_params = [
            _sp(p["id"], p["default"], p["description"])
            for p in req.get("params", [])
        ] or None

        implemented.append(
            comp.ImplementedRequirement(
                uuid=str(uuid.uuid4()),
                **{"control-id": ctrl_id},
                description=req["rule"],
                props=props,
                **{"set-parameters": set_params} if set_params else {},
                statements=[
                    comp.Statement(
                        **{"statement-id": f"{ctrl_id}_smt"},
                        uuid=str(uuid.uuid4()),
                        description=f"Rule: {req['rule']} | Check: {req['check']}",
                    )
                ],
            )
        )

    control_impl = comp.ControlImplementation(
        uuid=str(uuid.uuid4()),
        source=profile_href,
        description="Implementation of cncf-repo profile controls for a CNCF source repository.",
        **{"set-parameters": list(global_params.values())},
        **{"implemented-requirements": implemented},
    )

    component = comp.DefinedComponent(
        uuid=str(uuid.uuid4()),
        type="software",
        title="CNCF Source Repository",
        description=(
            "A generic CNCF source code repository component. Defines the rules, "
            "checks, and default parameter values for all controls selected by the "
            "cncf-repo profile. Specific repos override only the parameters that "
            "differ from these defaults."
        ),
        purpose="Provide a shared, reusable compliance baseline for CNCF source repositories.",
        **{"control-implementations": [control_impl]},
    )

    metadata = common.Metadata(
        title="CNCF Source Repository Component Definition",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
        props=[
            common.Property(
                name="description",
                value=(
                    "Shared component definition for CNCF source repositories. "
                    "Rules and checks are the same for all repos; "
                    "parameters may be overridden per repo."
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

    component_def = comp.ComponentDefinition(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        components=[component],
    )

    return comp.Model(**{"component-definition": component_def})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trestle-ws",
        default="trestle.ws",
        help="Path to the trestle workspace root (default: trestle.ws)",
    )
    args = parser.parse_args()

    trestle_ws = Path(args.trestle_ws)
    model = build_comp_def(trestle_ws)

    out_dir  = trestle_ws / "component-definitions" / "cncf-repo"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "component-definition.json"
    out_path.write_text(
        model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )

    n = len(REQUIREMENTS)
    print(f"Written: {out_path}  ({n} implemented requirements)")


if __name__ == "__main__":
    main()
