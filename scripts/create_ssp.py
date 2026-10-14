#!/usr/bin/env python3
"""Create the System Security Plan (SSP) and Assessment Plan (AP) for a repo.

Probes the repository to detect actual parameter values, reads the shared
cncf-repo component definition for rules + defaults, and writes:

  <trestle-ws>/system-security-plans/cncf-controls/system-security-plan.json
  <trestle-ws>/assessment-plans/cncf-controls/assessment-plan.json

Run once per repo (or whenever the repo structure changes materially).
The SSP captures this repo's specific parameter values — the Assessment Plan
references the SSP and defines what assess_repo.py will execute.

Usage:
    python scripts/create_ssp.py [--trestle-ws TRESTLE_WS]
                                 [--comp-def COMP_DEF]
                                 [--repo-root REPO_ROOT]
                                 [--repo-url REPO_URL]

Defaults:
    --trestle-ws   trestle.ws
    --comp-def     trestle.ws/component-definitions/cncf-repo/component-definition.json
    --repo-root    .  (current directory, auto-resolved)
    --repo-url     auto-detected from git remote origin
"""

import argparse
import json
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import ssp as ssp_mod
from trestle.oscal import assessment_plan as ap_mod
from trestle.oscal import common


# ---------------------------------------------------------------------------
# Repo probing — detect actual parameter values
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: Path) -> str:
    r = subprocess.run(["git"] + args, capture_output=True, text=True, cwd=cwd, timeout=15)
    return r.stdout.strip()


def detect_repo_url(repo_root: Path, override: str | None) -> str:
    if override:
        return override
    return _git(["remote", "get-url", "origin"], repo_root) or "https://github.com/unknown/unknown"


def detect_repo_name(repo_url: str) -> str:
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", repo_url)
    return m.group(1) if m else repo_url


def _first_existing(repo_root: Path, candidates: list[str]) -> str | None:
    for c in candidates:
        if (repo_root / c).exists():
            return c
    return None


def probe_params(repo_root: Path) -> dict[str, str]:
    """Probe the repo and return a dict of param-id → detected value."""
    params: dict[str, str] = {}

    # default-branch
    branch = _git(["symbolic-ref", "--short", "HEAD"], repo_root)
    params["default-branch"] = branch or "main"

    # pipeline-file
    params["pipeline-file"] = _first_existing(repo_root, [
        "Makefile", "Taskfile.yml", "Taskfile.yaml",
        ".github/workflows/ci.yml", ".github/workflows/build.yml",
        "Jenkinsfile",
    ]) or "Makefile"

    # dependency-file
    params["dependency-file"] = _first_existing(repo_root, [
        "requirements.txt", "go.mod", "package.json",
        "Cargo.toml", "pyproject.toml", "Pipfile",
    ]) or "requirements.txt"

    # lock-file
    params["lock-file"] = _first_existing(repo_root, [
        "requirements.lock", "go.sum", "package-lock.json",
        "yarn.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock",
    ]) or "requirements.lock"

    # codeowners-file
    params["codeowners-file"] = _first_existing(repo_root, [
        "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
    ]) or "CODEOWNERS"

    # contributing-file
    params["contributing-file"] = _first_existing(repo_root, [
        "CONTRIBUTING.md", ".github/CONTRIBUTING.md", "docs/CONTRIBUTING.md",
    ]) or "CONTRIBUTING.md"

    # security-policy-file
    params["security-policy-file"] = _first_existing(repo_root, [
        "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
    ]) or "SECURITY.md"

    # threat-model-file
    params["threat-model-file"] = _first_existing(repo_root, [
        "THREAT_MODEL.md", "THREAT-MODEL.md", "docs/THREAT_MODEL.md",
    ]) or "THREAT_MODEL.md"

    # sbom-output-path
    params["sbom-output-path"] = _first_existing(repo_root, [
        "sbom.json", "sbom.cdx.json", "dist/sbom.json", "docs/sbom.json",
    ]) or "sbom.json"

    # output-artifact-path — detect trestle catalog if present
    params["output-artifact-path"] = _first_existing(repo_root, [
        "trestle.ws/catalogs/cncf-controls/catalog.json",
        "dist/", "build/",
    ]) or "trestle.ws/catalogs/cncf-controls/catalog.json"

    # test-dir
    params["test-dir"] = _first_existing(repo_root, [
        "tests", "test", "spec", "__tests__",
    ]) or "tests"

    # Static defaults — same for all repos unless deliberately overridden
    params.setdefault("signed-commits-lookback", "10")
    params.setdefault("min-reviewers", "1")
    params.setdefault("mfa-enforcement-scope", "organization")
    params.setdefault("secrets-scan-extensions", "py,sh,yaml,yml,env,cfg,ini")
    params.setdefault("secrets-scan-exclude-paths", ".venv,trestle.ws,.git,download")
    params.setdefault("sast-tool", "bandit")
    params.setdefault("vulnerability-scanner", "pip-audit")
    params.setdefault("license-scanner", "pip-licenses")
    params.setdefault("trusted-registry-pattern", "pip install")
    params.setdefault("hash-pin-pattern", "--require-hashes")
    params.setdefault("git-config-file", ".git/config")
    params.setdefault("ssh-remote-pattern", "git@github\\.com")
    params.setdefault("env-setup-target", "venv")
    params.setdefault("all-target", "all")
    params.setdefault("test-target", "test")
    params.setdefault("validate-target", "validate-catalog")
    params.setdefault("sast-target", "sast")
    params.setdefault("pipeline-vuln-scan-target", "audit-deps")
    params.setdefault("sbom-target", "generate-sbom")
    params.setdefault("license-scan-target", "license-check")
    params.setdefault("sca-target", "sca")

    return params


# ---------------------------------------------------------------------------
# Load component definition — extract control IDs and their param IDs
# ---------------------------------------------------------------------------

def load_comp_def(comp_def_path: Path) -> tuple[list[str], dict[str, list[str]]]:
    """Return (ordered control_ids, {control_id: [param_ids]})."""
    data = json.loads(comp_def_path.read_text(encoding="utf-8"))
    control_ids: list[str] = []
    ctrl_params: dict[str, list[str]] = {}

    for component in data.get("component-definition", {}).get("components", []):
        for ci in component.get("control-implementations", []):
            for ir in ci.get("implemented-requirements", []):
                cid = ir["control-id"]
                control_ids.append(cid)
                pids = [sp["param-id"] for sp in ir.get("set-parameters", [])]
                ctrl_params[cid] = pids

    return control_ids, ctrl_params


# ---------------------------------------------------------------------------
# SSP builder
# ---------------------------------------------------------------------------

def build_ssp(
    repo_url: str,
    repo_name: str,
    params: dict[str, str],
    control_ids: list[str],
    ctrl_params: dict[str, list[str]],
    comp_uuid: str,
) -> ssp_mod.Model:
    now = datetime.now(tz=timezone.utc)
    profile_href = "trestle://profiles/cncf-repo/profile.json"

    metadata = common.Metadata(
        title=f"System Security Plan — {repo_name}",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
        parties=[
            common.Parties(
                uuid=str(uuid.uuid4()),
                type="organization",
                name=repo_name,
                links=[common.Link(href=repo_url, rel="canonical")],
            )
        ],
    )

    # System characteristics
    system_chars = ssp_mod.SystemCharacteristics(
        **{
            "system-ids": [
                common.SystemId(
                    **{"identifier-type": "https://github.com"},
                    id=repo_url,
                )
            ],
            "system-name": repo_name,
            "description": (
                f"Source code repository at {repo_url}. "
                "Assessed against the CNCF cncf-repo profile."
            ),
            "status": ssp_mod.Status1(state=ssp_mod.OperationalStateValidValues.operational),
            "authorization-boundary": ssp_mod.AuthorizationBoundary(
                description=(
                    "The authorization boundary is the source code repository itself, "
                    "including its build pipeline, dependency declarations, "
                    "branch protection settings, and committed artifacts."
                )
            ),
            "system-information": ssp_mod.SystemInformation(
                **{
                    "information-types": [
                        ssp_mod.InformationType(
                            uuid=str(uuid.uuid4()),
                            title="Source Code and Build Artifacts",
                            description=(
                                "Source code, scripts, configuration files, dependency "
                                "declarations, and generated OSCAL artifacts."
                            ),
                        )
                    ]
                }
            ),
        }
    )

    # System implementation — one component representing the repo
    system_impl = ssp_mod.SystemImplementation(
        components=[
            common.SystemComponent(
                uuid=comp_uuid,
                type="software",
                title="CNCF Source Repository",
                description=f"Source repository: {repo_url}",
                status=common.Status(
                    state=common.SystemComponentOperationalStateValidValues.operational
                ),
                links=[common.Link(href=repo_url, rel="reference")],
            )
        ],
        users=[
            common.SystemUser(
                uuid=str(uuid.uuid4()),
                title="Repository Contributor",
                **{"short-name": "contributor"},
                description="Developer with commit access to the repository.",
                **{"role-ids": ["developer"]},
            )
        ],
    )

    # Control implementation — one per control with repo-specific param values
    implemented = []
    for cid in control_ids:
        param_ids = ctrl_params.get(cid, [])
        set_params = [
            common.SetParameter(
                **{"param-id": pid},
                values=[params.get(pid, "")],
            )
            for pid in param_ids
            if params.get(pid)
        ] or None

        implemented.append(
            ssp_mod.ImplementedRequirement(
                uuid=str(uuid.uuid4()),
                **{"control-id": cid},
                **{"set-parameters": set_params} if set_params else {},
                **{
                    "by-components": [
                        ssp_mod.ByComponent(
                            **{"component-uuid": comp_uuid},
                            uuid=str(uuid.uuid4()),
                            description=f"Repository component implements {cid}.",
                        )
                    ]
                },
                remarks=(
                    f"Implementation of {cid} for repository {repo_name}. "
                    "Parameter values reflect the actual repository structure."
                ),
            )
        )

    ctrl_impl = ssp_mod.ControlImplementation(
        description=(
            "Implementation of cncf-repo profile controls. "
            "Parameter values are specific to this repository."
        ),
        **{"implemented-requirements": implemented},
    )

    ssp = ssp_mod.SystemSecurityPlan(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        **{"import-profile": ssp_mod.ImportProfile(href=profile_href)},
        **{"system-characteristics": system_chars},
        **{"system-implementation": system_impl},
        **{"control-implementation": ctrl_impl},
    )

    return ssp_mod.Model(**{"system-security-plan": ssp})


# ---------------------------------------------------------------------------
# Assessment Plan builder
# ---------------------------------------------------------------------------

def build_assessment_plan(
    ssp_href: str,
    control_ids: list[str],
    repo_name: str,
) -> ap_mod.Model:
    now = datetime.now(tz=timezone.utc)

    metadata = common.Metadata(
        title=f"Assessment Plan — {repo_name}",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
    )

    reviewed = common.ReviewedControls(
        description="All controls selected by the cncf-repo profile.",
        **{
            "control-selections": [
                common.ControlSelections(
                    **{
                        "include-controls": [
                            common.SelectControlById(**{"control-id": cid})
                            for cid in control_ids
                        ]
                    }
                )
            ]
        },
    )

    ap = ap_mod.AssessmentPlan(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        **{"import-ssp": common.ImportSsp(href=ssp_href)},
        **{"reviewed-controls": reviewed},
        **{
            "assessment-subjects": [
                common.AssessmentSubjectAll(
                    type="component",
                    description="The source code repository component.",
                    **{"include-all": common.IncludeAll()},
                )
            ]
        },
    )

    return ap_mod.Model(**{"assessment-plan": ap})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trestle-ws",  default="trestle.ws")
    parser.add_argument("--comp-def",    default="trestle.ws/component-definitions/cncf-repo/component-definition.json")
    parser.add_argument("--repo-root",   default=".")
    parser.add_argument("--repo-url",    default=None,
                        help="Repository URL (default: auto-detected from git remote origin)")
    args = parser.parse_args()

    trestle_ws  = Path(args.trestle_ws)
    comp_def_path = Path(args.comp_def)
    repo_root   = Path(args.repo_root).resolve()

    # Probe repo
    repo_url  = detect_repo_url(repo_root, args.repo_url)
    repo_name = detect_repo_name(repo_url)
    params    = probe_params(repo_root)

    print(f"Repository: {repo_url}")
    print(f"Branch:     {params['default-branch']}")
    print(f"Pipeline:   {params['pipeline-file']}")
    print(f"Deps:       {params['dependency-file']}")
    print(f"Lock file:  {params['lock-file']}")

    # Load component definition
    control_ids, ctrl_params = load_comp_def(comp_def_path)
    print(f"Controls:   {len(control_ids)} from component definition")

    comp_uuid = str(uuid.uuid4())

    # Write SSP
    ssp_dir = trestle_ws / "system-security-plans" / "cncf-controls"
    ssp_dir.mkdir(parents=True, exist_ok=True)
    ssp_path = ssp_dir / "system-security-plan.json"
    ssp_model = build_ssp(repo_url, repo_name, params, control_ids, ctrl_params, comp_uuid)
    ssp_path.write_text(
        ssp_model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )
    print(f"Written:    {ssp_path}")

    # Write Assessment Plan (references SSP via trestle internal href)
    ssp_href = "trestle://system-security-plans/cncf-controls/system-security-plan.json"
    ap_dir = trestle_ws / "assessment-plans" / "cncf-controls"
    ap_dir.mkdir(parents=True, exist_ok=True)
    ap_path = ap_dir / "assessment-plan.json"
    ap_model = build_assessment_plan(ssp_href, control_ids, repo_name)
    ap_path.write_text(
        ap_model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )
    print(f"Written:    {ap_path}")


if __name__ == "__main__":
    main()
