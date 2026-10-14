#!/usr/bin/env python3
"""Run the automated assessment for a repository.

Reads the SSP (for this repo's parameter values) and the shared component
definition (for check types and rules), runs automated evidence checks, and
writes:

  <trestle-ws>/assessment-results/<repo-slug>/assessment-results.json
  assessments/<org>/<repo>/assessment-results.json   (copy for badge hosting)
  assessments/<org>/<repo>/badge.json                (shields.io endpoint)
  assessments/<org>/<repo>/badge.svg                 (standalone SVG badge)

Badge levels:
  Not Assessed  — no assessment run
  Fail          — any MUST control is not-satisfied
  Pass          — all MUST satisfied + >= 50% of SHOULD
  Bronze        — all MUST satisfied + >= 60% of SHOULD
  Silver        — all MUST satisfied + >= 75% of SHOULD
  Gold          — all MUST satisfied + >= 90% of SHOULD

Usage:
    python scripts/assess_repo.py [--trestle-ws TRESTLE_WS]
                                  [--comp-def COMP_DEF]
                                  [--repo-root REPO_ROOT]
                                  [--repo-url REPO_URL]
                                  [--assessments-dir ASSESSMENTS_DIR]

Defaults:
    --trestle-ws       trestle.ws
    --comp-def         trestle.ws/component-definitions/cncf-repo/component-definition.json
    --repo-root        .
    --repo-url         auto-detected from git remote origin
    --assessments-dir  assessments
"""

import argparse
import json
import re
import subprocess
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import assessment_results as ar_mod
from trestle.oscal import common


# ---------------------------------------------------------------------------
# MUST controls — any failure causes overall Fail regardless of score
# ---------------------------------------------------------------------------

MUST_CONTROLS = {
    "CNSC-182",  # Commit and Tag Signing
    "CNSC-184",  # Secret Commit Prevention
    "CNSC-190",  # Branch Protection Rules
    "CNSC-198",  # Git Secret Prevention
    "CNSC-199",  # Commit Identity Enforcement
}

# Badge level thresholds (fraction of SHOULD controls that must be satisfied)
LEVELS = [
    ("gold",   0.90, "#FFD700"),
    ("silver", 0.75, "#C0C0C0"),
    ("bronze", 0.60, "#CD7F32"),
    ("pass",   0.50, "#4CAF50"),
]
FAIL_COLOR   = "#F44336"
FAIL_LABEL   = "fail"
NOT_ASSESSED = "not assessed"


# ---------------------------------------------------------------------------
# Check runners  (same logic as before, driven by param values from SSP)
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: Path) -> str:
    r = subprocess.run(["git"] + args, capture_output=True, text=True, cwd=cwd, timeout=15)
    return r.stdout.strip()


def check_file_exists(param_val: str, repo_root: Path) -> tuple[bool, str]:
    path = repo_root / param_val
    ok = path.exists()
    return ok, f"{'Found' if ok else 'Missing'}: {param_val}"


def check_file_contains(path_val: str, pattern_val: str, repo_root: Path) -> tuple[bool, str]:
    path = repo_root / path_val
    if not path.exists():
        return False, f"File not found: {path_val}"
    ok = bool(re.search(pattern_val, path.read_text(encoding="utf-8", errors="ignore")))
    return ok, f"Pattern {'found' if ok else 'not found'} in {path_val}: {pattern_val}"


def check_no_secrets(extensions: str, exclude_paths: str, repo_root: Path) -> tuple[bool, str]:
    secret_pattern = re.compile(
        r"(?i)(password|passwd|secret|api.?key|private.?key|token)\s*=\s*['\"][^'\"]{6,}"
    )
    exts = [e.strip() for e in extensions.split(",")]
    excludes = [e.strip() for e in exclude_paths.split(",")]
    findings = []
    for ext in exts:
        for fpath in repo_root.rglob(f"*.{ext}"):
            if any(p in fpath.parts for p in excludes):
                continue
            try:
                if secret_pattern.search(fpath.read_text(encoding="utf-8", errors="ignore")):
                    findings.append(str(fpath.relative_to(repo_root)))
            except OSError:
                continue
    ok = len(findings) == 0
    return ok, "No hardcoded secrets detected" if ok else f"Potential secrets in: {', '.join(findings)}"


def check_git_signed(lookback: str, repo_root: Path) -> tuple[bool, str]:
    n = int(lookback) if lookback.isdigit() else 10
    result = _git(["log", f"-{n}", "--format=%G?"], repo_root)
    sigs = [s for s in result.splitlines() if s.strip()]
    if not sigs:
        return False, "No commits found"
    bad = [s for s in sigs if s.strip() == "N"]
    ok = len(bad) == 0
    return ok, f"{len(sigs) - len(bad)}/{len(sigs)} commits signed"


def check_branch_protected(branch: str, repo_root: Path) -> tuple[bool, str]:
    remote = _git(["remote", "get-url", "origin"], repo_root)
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", remote)
    if not m:
        return False, f"Cannot parse GitHub remote: {remote}"
    owner_repo = m.group(1)
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner_repo}/branches/{branch}",
            headers={"Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        protected = data.get("protected", False)
        return protected, f"Branch '{branch}' protected={protected}"
    except Exception as exc:
        return False, f"GitHub API error: {exc}"


def check_makefile_target(target: str, pipeline_file: str, repo_root: Path) -> tuple[bool, str]:
    mf = repo_root / pipeline_file
    if not mf.exists():
        return False, f"{pipeline_file} not found"
    ok = bool(re.search(rf"^{re.escape(target)}\s*:", mf.read_text(encoding="utf-8"), re.MULTILINE))
    return ok, f"Target '{target}' {'found' if ok else 'not found'} in {pipeline_file}"


# ---------------------------------------------------------------------------
# Dispatch check by type declared in comp-def check field
# Parses: "check-type | param: p1; p2"
# ---------------------------------------------------------------------------

def run_check(check_spec: str, param_values: dict[str, str], repo_root: Path) -> tuple[bool, str]:
    """Parse the check spec from the component definition and run it."""
    parts = [p.strip() for p in check_spec.split("|")]
    check_type = parts[0].strip()
    # extract referenced param names
    pnames: list[str] = []
    if len(parts) > 1:
        param_part = parts[1].replace("param:", "").strip()
        pnames = [p.strip() for p in param_part.split(";") if p.strip()]

    def pv(name: str, default: str = "") -> str:
        return param_values.get(name, default)

    if check_type == "file-exists":
        return check_file_exists(pv(pnames[0]) if pnames else "", repo_root)

    if check_type == "file-contains":
        return check_file_contains(
            pv(pnames[0]) if len(pnames) > 0 else "",
            pv(pnames[1]) if len(pnames) > 1 else "",
            repo_root,
        )

    if check_type == "no-secrets-in-files":
        return check_no_secrets(
            pv("secrets-scan-extensions", "py,sh,yaml,yml,env,cfg,ini"),
            pv("secrets-scan-exclude-paths", ".venv,trestle.ws,.git,download"),
            repo_root,
        )

    if check_type == "git-commits-signed":
        return check_git_signed(pv("signed-commits-lookback", "10"), repo_root)

    if check_type == "git-branch-protected":
        return check_branch_protected(pv("default-branch", "main"), repo_root)

    if check_type == "makefile-target":
        return check_makefile_target(
            pv(pnames[0]) if pnames else "",
            pv("pipeline-file", "Makefile"),
            repo_root,
        )

    if check_type == "manual":
        return False, "Manual check — cannot be automated."

    return False, f"Unknown check type: {check_type}"


# ---------------------------------------------------------------------------
# Load SSP param values per control
# ---------------------------------------------------------------------------

def load_ssp_params(ssp_path: Path) -> tuple[str, dict[str, dict[str, str]]]:
    """Return (repo_url, {control_id: {param_id: value}})."""
    data = json.loads(ssp_path.read_text(encoding="utf-8"))
    ssp = data.get("system-security-plan", {})

    # repo URL from system-ids
    repo_url = ""
    for sid in ssp.get("system-characteristics", {}).get("system-ids", []):
        repo_url = sid.get("id", "")
        break

    ctrl_params: dict[str, dict[str, str]] = {}
    for ir in ssp.get("control-implementation", {}).get("implemented-requirements", []):
        cid = ir["control-id"]
        params: dict[str, str] = {}
        for sp in ir.get("set-parameters", []):
            vals = sp.get("values", [])
            params[sp["param-id"]] = vals[0] if vals else ""
        ctrl_params[cid] = params

    return repo_url, ctrl_params


# ---------------------------------------------------------------------------
# Load comp-def check specs and global default params
# ---------------------------------------------------------------------------

def load_comp_def(comp_def_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Return ({control_id: check_spec}, {param_id: default_value})."""
    data = json.loads(comp_def_path.read_text(encoding="utf-8"))
    check_specs: dict[str, str] = {}
    global_defaults: dict[str, str] = {}

    for component in data.get("component-definition", {}).get("components", []):
        for ci in component.get("control-implementations", []):
            # global defaults at the control-implementation level
            for sp in ci.get("set-parameters", []):
                vals = sp.get("values", [])
                global_defaults[sp["param-id"]] = vals[0] if vals else ""

            for ir in ci.get("implemented-requirements", []):
                cid = ir["control-id"]
                # extract check spec from props
                for prop in ir.get("props", []):
                    if prop.get("name") == "check":
                        check_specs[cid] = prop["value"]
                        break

    return check_specs, global_defaults


# ---------------------------------------------------------------------------
# Badge computation
# ---------------------------------------------------------------------------

def compute_badge(results: list[dict]) -> tuple[str, str]:
    """Return (level_label, hex_color)."""
    assessed = [r for r in results if r["status"] != "not-applicable"]
    if not assessed:
        return NOT_ASSESSED, "#9E9E9E"

    must    = [r for r in assessed if r["control_id"] in MUST_CONTROLS]
    must_fail = [r for r in must if r["status"] == "not-satisfied"]
    if must_fail:
        return FAIL_LABEL, FAIL_COLOR

    should      = [r for r in assessed if r["control_id"] not in MUST_CONTROLS]
    should_pass = [r for r in should if r["status"] == "satisfied"]
    score       = len(should_pass) / len(should) if should else 1.0

    for label, threshold, color in LEVELS:
        if score >= threshold:
            return label, color

    return FAIL_LABEL, FAIL_COLOR


def write_badge_json(level: str, color: str, satisfied: int, total: int, out_path: Path) -> None:
    badge = {
        "schemaVersion": 1,
        "label": "CNCF Controls",
        "message": f"{level} ({satisfied}/{total})",
        "color": color.lstrip("#"),
        "labelColor": "555555",
        "style": "flat",
    }
    out_path.write_text(json.dumps(badge, indent=2), encoding="utf-8")


def write_badge_svg(level: str, color: str, satisfied: int, total: int, out_path: Path) -> None:
    label      = "CNCF Controls"
    message    = f"{level} ({satisfied}/{total})"
    label_w    = len(label) * 7 + 10
    message_w  = len(message) * 7 + 10
    total_w    = label_w + message_w

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total_w}" height="20" fill="#555"/>
  <rect rx="3" x="{label_w}" width="{message_w}" height="20" fill="{color}"/>
  <rect rx="3" width="{total_w}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_w // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_w // 2}" y="14">{label}</text>
    <text x="{label_w + message_w // 2}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{label_w + message_w // 2}" y="14">{message}</text>
  </g>
</svg>"""
    out_path.write_text(svg, encoding="utf-8")


# ---------------------------------------------------------------------------
# OSCAL Assessment Results builder
# ---------------------------------------------------------------------------

def build_ar(results: list[dict], repo_url: str, tool_uuid: str) -> ar_mod.Model:
    now = datetime.now(tz=timezone.utc)

    metadata = common.Metadata(
        title=f"Assessment Results — {repo_url}",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
        parties=[common.Parties(uuid=tool_uuid, type="tool", name="assess_repo.py")],
    )

    observations, findings = [], []
    assessed = [r for r in results if r["status"] != "not-applicable"]

    for r in assessed:
        obs_uuid = str(uuid.uuid4())
        observations.append(common.Observation(
            uuid=obs_uuid,
            title=f"Assessment of {r['control_id']}",
            description=r["message"],
            methods=["EXAMINE"],
            types=["finding"],
            collected=now,
        ))
        findings.append(common.Finding(
            uuid=str(uuid.uuid4()),
            title=f"{r['control_id']} — {r['status']}",
            description=r["message"],
            target=common.FindingTarget(
                type="statement-id",
                **{"target-id": f"{r['control_id']}_smt"},
                status=common.ObjectiveStatus(
                    state=(
                        common.ObjectiveStatusStateValidValues.satisfied
                        if r["status"] == "satisfied"
                        else common.ObjectiveStatusStateValidValues.not_satisfied
                    ),
                ),
            ),
            origins=[common.Origin(actors=[
                common.OriginActor(
                    type=common.OriginActorValidValues.tool,
                    **{"actor-uuid": tool_uuid},
                )
            ])],
            **{"related-observations": [
                common.RelatedObservation(**{"observation-uuid": obs_uuid})
            ]},
        ))

    reviewed = common.ReviewedControls(
        **{"control-selections": [
            common.ControlSelections(
                **{"include-controls": [
                    common.SelectControlById(**{"control-id": r["control_id"]})
                    for r in assessed
                ]}
            )
        ]}
    )

    result = ar_mod.Result(
        uuid=str(uuid.uuid4()),
        title="Automated Repository Assessment",
        description=f"Automated assessment of {repo_url} against the cncf-repo profile.",
        start=now,
        end=now,
        **{"reviewed-controls": reviewed},
        observations=observations or None,
        findings=findings or None,
    )

    assessment_results = ar_mod.AssessmentResults(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        **{"import-ap": ar_mod.ImportAp(href="trestle://assessment-plans/cncf-controls/assessment-plan.json")},
        results=[result],
    )

    return ar_mod.Model(**{"assessment-results": assessment_results})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trestle-ws",       default="trestle.ws")
    parser.add_argument("--comp-def",         default="trestle.ws/component-definitions/cncf-repo/component-definition.json")
    parser.add_argument("--repo-root",        default=".")
    parser.add_argument("--repo-url",         default=None)
    parser.add_argument("--assessments-dir",  default="assessments")
    args = parser.parse_args()

    trestle_ws      = Path(args.trestle_ws)
    comp_def_path   = Path(args.comp_def)
    repo_root       = Path(args.repo_root).resolve()
    assessments_dir = Path(args.assessments_dir)

    # Derive repo slug from SSP — find the SSP in trestle.ws
    ssp_candidates = list((trestle_ws / "system-security-plans").glob("*/system-security-plan.json"))
    if not ssp_candidates:
        raise SystemExit("No SSP found in trestle.ws — run make create-ssp first.")
    ssp_path = ssp_candidates[0]
    repo_slug = ssp_path.parent.name

    repo_url, ssp_ctrl_params = load_ssp_params(ssp_path)
    check_specs, global_defaults = load_comp_def(comp_def_path)

    # Override repo_url if passed explicitly
    if args.repo_url:
        repo_url = args.repo_url

    print(f"Assessing: {repo_url}")
    print(f"SSP:       {ssp_path}")

    # Run checks
    results = []
    for ctrl_id, check_spec in check_specs.items():
        # Merge: global defaults < SSP params for this control
        merged = {**global_defaults, **ssp_ctrl_params.get(ctrl_id, {})}

        passed, message = run_check(check_spec, merged, repo_root)
        status = "satisfied" if passed else "not-satisfied"
        results.append({"control_id": ctrl_id, "status": status, "message": message})

    # Summary
    satisfied     = sum(1 for r in results if r["status"] == "satisfied")
    not_satisfied = sum(1 for r in results if r["status"] == "not-satisfied")
    print(f"  satisfied:     {satisfied}")
    print(f"  not-satisfied: {not_satisfied}")

    # Badge
    level, color = compute_badge(results)
    total_assessed = satisfied + not_satisfied
    print(f"  badge level:   {level}  ({satisfied}/{total_assessed})")

    # Write OSCAL Assessment Results into trestle workspace
    tool_uuid = str(uuid.uuid4())
    ar_model  = build_ar(results, repo_url, tool_uuid)
    ar_dir    = trestle_ws / "assessment-results" / repo_slug
    ar_dir.mkdir(parents=True, exist_ok=True)
    ar_path   = ar_dir / "assessment-results.json"
    ar_path.write_text(
        ar_model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )
    print(f"Written:   {ar_path}")

    # Derive org/repo from repo_url for assessments/ output dir
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", repo_url)
    org_repo = m.group(1) if m else repo_slug
    out_dir  = assessments_dir / org_repo
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy AR
    ar_copy = out_dir / "assessment-results.json"
    ar_copy.write_text(ar_path.read_text(encoding="utf-8"), encoding="utf-8")

    # Badge JSON (shields.io endpoint)
    badge_json_path = out_dir / "badge.json"
    write_badge_json(level, color, satisfied, total_assessed, badge_json_path)
    print(f"Written:   {badge_json_path}")

    # Badge SVG
    badge_svg_path = out_dir / "badge.svg"
    write_badge_svg(level, color, satisfied, total_assessed, badge_svg_path)
    print(f"Written:   {badge_svg_path}")

    # Print the README embed snippet
    raw_base = "https://raw.githubusercontent.com/oscal-compass-lab/cncf-controls/main"
    badge_url = f"{raw_base}/assessments/{org_repo}/badge.json"
    results_url = f"https://github.com/oscal-compass-lab/cncf-controls/tree/main/assessments/{org_repo}"
    print(f"\nAdd this to your README.md:")
    print(f"[![CNCF Controls](https://img.shields.io/endpoint?url={badge_url})]({results_url})")


if __name__ == "__main__":
    main()
