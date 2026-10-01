#!/usr/bin/env python3
"""Fail closed on contradictory pack status and coverage claims."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    errors = []
    manifest = json.loads((root / "development-pack/PACK_MANIFEST.json").read_text())
    blueprint = (root / manifest["source_blueprint"]).read_text()
    review = root / manifest["review"]
    if not review.is_file():
        errors.append("review missing")
    unit_ids = set(re.findall(r"\bDU-\d{3}\b", blueprint))
    if len(unit_ids) != manifest["development_unit_count"]:
        errors.append(f"DU count mismatch: {len(unit_ids)}")
    if not set(manifest["partial_units"]).issubset(unit_ids):
        errors.append("partial DU absent from blueprint")
    if manifest["production_qualified"] and not manifest["runtime_qualified"]:
        errors.append("production qualification without runtime qualification")
    if manifest["runtime_qualified"] and not manifest["build_ready"]:
        errors.append("runtime qualification without build readiness")
    if manifest["owner_accepted"] and not manifest["production_qualified"]:
        errors.append("owner acceptance without production qualification")
    if manifest["build_ready"] and manifest["blocked_external"]:
        errors.append("build ready despite unresolved external blockers")
    if manifest["repository"] != "Vanguduza/hosting-":
        errors.append("unexpected repository identity")
    return errors


if __name__ == "__main__":
    issues = check()
    for issue in issues:
        print("FAIL:", issue, file=sys.stderr)
    if issues:
        sys.exit(1)
    print("Pack consistency: PASS; runtime/commercial certification remains separate")
