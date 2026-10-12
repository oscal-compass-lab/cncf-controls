#!/usr/bin/env python3
"""Generic repo assessment engine.

Reads an assessment config YAML, runs automated evidence checks against the
local repository, and writes an OSCAL Assessment Results JSON into the trestle
workspace.

Usage:
    python scripts/assess_repo.py [--config CONFIG] [--trestle-ws TRESTLE_WS]
                                  [--catalog-name CATALOG_NAME] [--repo-root REPO_ROOT]

Defaults:
    --config        scripts/assessments/config.yaml
    --trestle-ws    trestle.ws
    --catalog-name  cncf-controls
    --repo-root     . (current directory)

Output:
    <trestle-ws>/assessment-results/<catalog-name>/assessment-results.json
"""

import argparse
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from trestle.oscal import OSCAL_VERSION
from trestle.oscal import assessment_results as ar
from trestle.oscal import common


# ---------------------------------------------------------------------------
# Check runners
# ---------------------------------------------------------------------------

def check_file_exists(params: dict, repo_root: Path) -> tuple[bool, str]:
    path = repo_root / params["path"]
    ok = path.exists()
    return ok, f"{'Found' if ok else 'Missing'}: {params['path']}"


def check_file_contains(params: dict, repo_root: Path) -> tuple[bool, str]:
    path = repo_root / params["path"]
    if not path.exists():
        return False, f"File not found: {params['path']}"
    pattern = params["pattern"]
    text = path.read_text(encoding="utf-8", errors="ignore")
    ok = bool(re.search(pattern, text))
    return ok, f"Pattern {'found' if ok else 'not found'} in {params['path']}: {pattern}"


def check_no_secrets_in_files(params: dict, repo_root: Path) -> tuple[bool, str]:
    patterns = params.get("patterns", [
        r"(?i)(password|passwd|secret|api.?key|private.?key|token)\s*=\s*['\"][^'\"]{6,}",
    ])
    extensions = params.get("extensions", ["py", "sh", "yaml", "yml", "json", "env", "cfg", "ini"])
    findings = []
    for ext in extensions:
        for fpath in repo_root.rglob(f"*.{ext}"):
            # skip venv, trestle workspace, git internals
            if any(p in fpath.parts for p in [".venv", "trestle.ws", ".git", "download"]):
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pat in patterns:
                if re.search(pat, text):
                    findings.append(str(fpath.relative_to(repo_root)))
    ok = len(findings) == 0
    msg = "No hardcoded secrets detected" if ok else f"Potential secrets in: {', '.join(findings)}"
    return ok, msg


def check_git_commits_signed(params: dict, repo_root: Path) -> tuple[bool, str]:
    n = params.get("last_n_commits", 10)
    try:
        result = subprocess.run(
            ["git", "log", f"-{n}", "--format=%G?"],
            capture_output=True, text=True, cwd=repo_root, timeout=15,
        )
        signatures = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
        if not signatures:
            return False, "No commits found"
        unsigned = [s for s in signatures if s not in ("G", "U", "X", "Y", "E")]
        # G=good, U=untrusted, X=expired key, Y=expired sig, E=missing key — all are signed
        bad = [s for s in signatures if s == "N"]  # N = not signed
        ok = len(bad) == 0
        return ok, f"{len(signatures) - len(bad)}/{len(signatures)} commits signed"
    except Exception as exc:
        return False, f"git error: {exc}"


def check_git_branch_protected(params: dict, repo_root: Path) -> tuple[bool, str]:
    branch = params.get("branch", "main")
    try:
        # Get remote URL to derive owner/repo
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=repo_root, timeout=10,
        )
        remote = result.stdout.strip()
        m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", remote)
        if not m:
            return False, f"Cannot parse GitHub remote: {remote}"
        owner_repo = m.group(1)
        import urllib.request
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner_repo}/branches/{branch}",
            headers={"Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json
            data = json.loads(resp.read())
        protected = data.get("protected", False)
        return protected, f"Branch '{branch}' protected={protected}"
    except Exception as exc:
        return False, f"GitHub API error: {exc}"


def check_makefile_target(params: dict, repo_root: Path) -> tuple[bool, str]:
    target = params["target"]
    makefile = repo_root / params.get("makefile", "Makefile")
    if not makefile.exists():
        return False, "Makefile not found"
    text = makefile.read_text(encoding="utf-8")
    ok = bool(re.search(rf"^{re.escape(target)}\s*:", text, re.MULTILINE))
    return ok, f"Makefile target '{target}' {'found' if ok else 'not found'}"


# Registry of check runners
CHECKERS = {
    "file-exists":          check_file_exists,
    "file-contains":        check_file_contains,
    "no-secrets-in-files":  check_no_secrets_in_files,
    "git-commits-signed":   check_git_commits_signed,
    "git-branch-protected": check_git_branch_protected,
    "makefile-target":      check_makefile_target,
}


# ---------------------------------------------------------------------------
# Assessment engine
# ---------------------------------------------------------------------------

def run_checks(evidence_list: list[dict], repo_root: Path) -> tuple[bool, list[str]]:
    """Run all checks for a control. Returns (overall_pass, [messages])."""
    messages = []
    overall = True
    for ev in evidence_list:
        check_type = ev.get("check")
        if not check_type:
            continue
        runner = CHECKERS.get(check_type)
        if not runner:
            messages.append(f"Unknown check type: {check_type}")
            overall = False
            continue
        passed, msg = runner(ev.get("params", {}), repo_root)
        messages.append(msg)
        if not passed:
            overall = False
    return overall, messages


def assess(config: dict, repo_root: Path) -> list[dict]:
    """
    Returns a list of result dicts:
      {control_id, status, state, remarks, messages}
    status: 'satisfied' | 'not-satisfied' | 'not-applicable'
    """
    results = []
    for entry in config.get("controls", []):
        ctrl_id  = entry["id"]
        declared = entry.get("status", "not-satisfied")  # declared baseline
        remarks  = entry.get("remarks", "")
        evidence = entry.get("evidence", [])

        if declared == "not-applicable":
            results.append({
                "control_id": ctrl_id,
                "status":     "not-applicable",
                "state":      "not-satisfied",   # OSCAL FindingTarget needs a state
                "remarks":    remarks or "Not applicable to this repository context.",
                "messages":   [],
            })
            continue

        if evidence:
            passed, messages = run_checks(evidence, repo_root)
            state = "satisfied" if passed else "not-satisfied"
        else:
            # No automated check — use declared status as-is
            state    = declared
            messages = [remarks] if remarks else ["Manual declaration — no automated check."]

        results.append({
            "control_id": ctrl_id,
            "status":     state,
            "state":      state,
            "remarks":    remarks,
            "messages":   messages,
        })
    return results


# ---------------------------------------------------------------------------
# OSCAL builder
# ---------------------------------------------------------------------------

def build_assessment_results(
    results: list[dict],
    catalog_name: str,
    trestle_ws: Path,
    tool_uuid: str,
) -> ar.Model:
    now = datetime.now(tz=timezone.utc)

    # Metadata
    metadata = common.Metadata(
        title="cncf-controls Repo Assessment Results",
        **{"last-modified": now},
        version="1.0",
        **{"oscal-version": OSCAL_VERSION},
        roles=[common.Role(id="assessor", title="Automated Assessor")],
        parties=[
            common.Parties(
                uuid=tool_uuid,
                type="tool",
                name="assess_repo.py",
            )
        ],
    )

    # One Finding per control (skip not-applicable)
    findings = []
    observations = []
    for r in results:
        ctrl_id = r["control_id"]
        state   = r["state"]
        status  = r["status"]

        if status == "not-applicable":
            continue

        obs_uuid = str(uuid.uuid4())
        obs = common.Observation(
            uuid=obs_uuid,
            title=f"Assessment of {ctrl_id}",
            description="; ".join(r["messages"]) or r["remarks"] or "No details.",
            methods=["EXAMINE"],
            types=["finding"],
        )
        observations.append(obs)

        finding = common.Finding(
            uuid=str(uuid.uuid4()),
            title=f"{ctrl_id} — {'satisfied' if state == 'satisfied' else 'not satisfied'}",
            description="; ".join(r["messages"]) or r["remarks"] or "No details.",
            target=common.FindingTarget(
                type="statement-id",
                **{"target-id": f"{ctrl_id}_smt"},
                status=common.ObjectiveStatus(
                    state=common.ObjectiveStatusStateValidValues.satisfied
                    if state == "satisfied"
                    else common.ObjectiveStatusStateValidValues.not_satisfied,
                    remarks=r["remarks"] or None,
                ),
            ),
            origins=[
                common.Origin(
                    actors=[
                        common.OriginActor(
                            type=common.OriginActorValidValues.tool,
                            **{"actor-uuid": tool_uuid},
                        )
                    ]
                )
            ],
            **{"related-observations": [common.RelatedObservation(**{"observation-uuid": obs_uuid})]},
        )
        findings.append(finding)

    # reviewed-controls: include all assessed controls
    assessed_ids = [r["control_id"] for r in results if r["status"] != "not-applicable"]
    reviewed = common.ReviewedControls(
        **{
            "control-selections": [
                common.ControlSelections(
                    **{
                        "include-controls": [
                            common.SelectControlById(**{"control-id": cid})
                            for cid in assessed_ids
                        ]
                    }
                )
            ]
        }
    )

    result = ar.Result(
        uuid=str(uuid.uuid4()),
        title="Automated Repository Assessment",
        description=(
            "Automated assessment of the cncf-controls repository against the "
            "CNCF Cloud Native Security Controls catalog."
        ),
        start=now,
        end=now,
        **{"reviewed-controls": reviewed},
        observations=observations or None,
        findings=findings or None,
    )

    assessment_results = ar.AssessmentResults(
        uuid=str(uuid.uuid4()),
        metadata=metadata,
        **{"import-ap": ar.ImportAp(href=f"#{catalog_name}")},
        results=[result],
    )

    return ar.Model(**{"assessment-results": assessment_results})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",       default="scripts/assessments/config.yaml")
    parser.add_argument("--trestle-ws",   default="trestle.ws")
    parser.add_argument("--catalog-name", default="cncf-controls")
    parser.add_argument("--repo-root",    default=".")
    args = parser.parse_args()

    config_path  = Path(args.config)
    trestle_ws   = Path(args.trestle_ws)
    repo_root    = Path(args.repo_root).resolve()
    catalog_name = args.catalog_name

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    print(f"Assessing {len(config.get('controls', []))} controls against {repo_root} ...")
    results = assess(config, repo_root)

    satisfied     = sum(1 for r in results if r["status"] == "satisfied")
    not_satisfied = sum(1 for r in results if r["status"] == "not-satisfied")
    not_applicable = sum(1 for r in results if r["status"] == "not-applicable")
    print(f"  satisfied:      {satisfied}")
    print(f"  not-satisfied:  {not_satisfied}")
    print(f"  not-applicable: {not_applicable}")

    tool_uuid = str(uuid.uuid4())
    model = build_assessment_results(results, catalog_name, trestle_ws, tool_uuid)

    out_dir = trestle_ws / "assessment-results" / catalog_name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "assessment-results.json"
    out_path.write_text(
        model.model_dump_json(indent=2, exclude_none=True, by_alias=True),
        encoding="utf-8",
    )
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
