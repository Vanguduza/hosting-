#!/usr/bin/env python3
"""Evidence-bound artifact admission; requires installed Cosign, Trivy and Syft."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import psycopg


def run(args, *, timeout=600):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} rejected the artifact (exit {result.returncode})")
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="Registry image reference ending in @sha256:<64 hex>")
    parser.add_argument("--source-commit", required=True, help="Audited 40-character Git commit")
    parser.add_argument("--policy-revision", required=True)
    parser.add_argument("--cosign-public-key", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}", args.image):
        parser.error("image must be digest-pinned")
    if not re.fullmatch(r"[a-f0-9]{40}", args.source_commit):
        parser.error("invalid source commit")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args.policy_revision):
        parser.error("invalid policy revision")
    if not args.cosign_public_key.is_file():
        parser.error("trusted Cosign public key missing")
    dsn = os.environ.get("HOSTING_MIGRATION_DSN")
    if not dsn:
        parser.error("HOSTING_MIGRATION_DSN required (private operator database connection)")

    verification = json.loads(run(["cosign", "verify", "--key", str(args.cosign_public_key), args.image]))
    if not isinstance(verification, list) or not verification:
        raise RuntimeError("Cosign returned no verification proof")
    for item in verification:
        expected = args.image.rsplit("@", 1)[-1]
        actual = item.get("critical", {}).get("image", {}).get("docker-manifest-digest")
        if actual != expected:
            raise RuntimeError("Signature proof digest mismatch")
    scan = run(["trivy", "image", "--scanners", "vuln,secret", "--severity", "HIGH,CRITICAL",
                "--exit-code", "1", "--format", "json", args.image])
    scan_json = json.loads(scan)
    if not isinstance(scan_json, dict):
        raise RuntimeError("Invalid Trivy scan output")
    sbom = run(["syft", "scan", args.image, "-o", "cyclonedx-json"])
    sbom_json = json.loads(sbom)
    if not isinstance(sbom_json, dict) or sbom_json.get("bomFormat") != "CycloneDX":
        raise RuntimeError("Invalid CycloneDX SBOM")
    artifact_id = hashlib.sha256(args.image.encode()).hexdigest()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.stat().st_mode & 0o077:
        raise RuntimeError("Evidence directory must be accessible only by its owner")
    receipt = {
        "image": args.image, "source_commit": args.source_commit,
        "policy_revision": args.policy_revision, "verified_at": datetime.now(timezone.utc).isoformat(),
        "cosign_key_sha256": hashlib.sha256(args.cosign_public_key.read_bytes()).hexdigest(),
        "signature_count": len(verification),
        "trivy_sha256": hashlib.sha256(scan.encode()).hexdigest(),
        "sbom_sha256": hashlib.sha256(sbom.encode()).hexdigest(),
    }
    for name, data in (("cosign", json.dumps(verification)), ("trivy", scan), ("sbom", sbom),
                       ("receipt", json.dumps(receipt, indent=2))):
        path = evidence / f"{artifact_id}.{name}.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(data)
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        with conn.transaction():
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                         "VALUES (%s,%s,%s,%s,%s::jsonb)",
                         (args.image, receipt["sbom_sha256"], args.source_commit, args.policy_revision, json.dumps(receipt)))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
