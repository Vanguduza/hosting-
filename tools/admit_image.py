#!/usr/bin/env python3
"""Evidence-bound artifact admission; requires installed Cosign, Trivy and Syft."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg


def run(args, *, timeout=600):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} rejected the artifact (exit {result.returncode})")
    return result.stdout


def proof_json(contents):
    try:
        return json.loads(contents)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Stored admission proof is invalid JSON") from exc


def stored_evidence(directory, artifact_id, image, commit, policy, key_sha256):
    """Read a fully written local receipt, including the three hashed proofs."""
    paths = {name: directory / f"{artifact_id}.{name}.json"
             for name in ("cosign", "trivy", "sbom", "receipt")}
    if not paths["receipt"].exists():
        if any(path.exists() for path in paths.values()):
            raise RuntimeError("Incomplete admission evidence requires operator reconciliation")
        return None
    for path in paths.values():
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("Admission evidence file is missing or unsafe")
    receipt = proof_json(paths["receipt"].read_text())
    if not isinstance(receipt, dict):
        raise RuntimeError("Stored admission receipt invalid")
    if (receipt.get("image"), receipt.get("source_commit"), receipt.get("policy_revision"),
            receipt.get("cosign_key_sha256")) != (image, commit, policy, key_sha256):
        raise RuntimeError("Admission replay differs from stored proof")
    proofs = {name: paths[name].read_bytes() for name in ("cosign", "trivy", "sbom")}
    cosign = proof_json(proofs["cosign"])
    if (not isinstance(cosign, list) or not cosign or receipt.get("signature_count") != len(cosign) or
            any(not isinstance(item, dict) or item.get("critical", {}).get("image", {}).get("docker-manifest-digest") !=
                image.rsplit("@", 1)[-1] for item in cosign)):
        raise RuntimeError("Stored image signature proof invalid")
    sbom = proof_json(proofs["sbom"])
    if (not isinstance(proof_json(proofs["trivy"]), dict) or
            not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or
            receipt.get("trivy_sha256") != hashlib.sha256(proofs["trivy"]).hexdigest() or
            receipt.get("sbom_sha256") != hashlib.sha256(proofs["sbom"]).hexdigest()):
        raise RuntimeError("Stored scan or SBOM proof invalid")
    return receipt


def save_proof(directory, artifact_id, name, contents):
    target = directory / f"{artifact_id}.{name}.json"
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".admission-", delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents.encode())
            file.flush()
            os.fsync(file.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if (target.is_symlink() or not target.is_file() or target.stat().st_mode & 0o077 or
                        target.read_bytes() != contents.encode()):
                    raise RuntimeError("Admission evidence replay differs") from None
        finally:
            temporary.unlink()
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


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
    dsn = os.environ.get("HOSTING_ADMISSION_DSN")
    if not dsn:
        parser.error("HOSTING_ADMISSION_DSN required (private restricted builder connection)")
    # Reject accidental privileged operator credentials before scanning or
    # writing evidence. An admission worker must never own schema or tenant state.
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        role = conn.execute("SELECT current_user,rolsuper,rolbypassrls FROM pg_roles "
                            "WHERE rolname=current_user").fetchone()
        if not role or role != ("hosting_admitter", False, False):
            raise RuntimeError("A restricted hosting_admitter connection is required")

    if args.evidence_dir.is_symlink():
        raise RuntimeError("Evidence directory must not be a symlink")
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.is_symlink() or evidence.stat().st_mode & 0o077:
        raise RuntimeError("Evidence directory must be accessible only by its owner")
    artifact_id = hashlib.sha256(args.image.encode()).hexdigest()
    key_sha256 = hashlib.sha256(args.cosign_public_key.read_bytes()).hexdigest()
    existing = stored_evidence(evidence, artifact_id, args.image, args.source_commit,
                               args.policy_revision, key_sha256)
    if existing:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            row = conn.execute("SELECT source_commit,policy_revision,sbom_sha256,verification_receipt "
                               "FROM hosting.artifact_admissions WHERE image=%s", (args.image,)).fetchone()
            if row:
                if (row[0], row[1], row[2], row[3]) != (args.source_commit, args.policy_revision,
                                                       existing["sbom_sha256"], existing):
                    raise RuntimeError("Admission database proof differs from local evidence")
                print(json.dumps(existing, sort_keys=True))
                return
        # A process may have stopped after writing all evidence and before
        # committing the database row. Reinsert only the exact local receipt.
        receipt = existing
    else:
        receipt = None
    if receipt is None:
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
        receipt = {
            "image": args.image, "source_commit": args.source_commit,
            "policy_revision": args.policy_revision, "verified_at": datetime.now(timezone.utc).isoformat(),
            "cosign_key_sha256": key_sha256, "signature_count": len(verification),
            "trivy_sha256": hashlib.sha256(scan.encode()).hexdigest(),
            "sbom_sha256": hashlib.sha256(sbom.encode()).hexdigest(),
        }
        for name, data in (("cosign", json.dumps(verification)), ("trivy", scan), ("sbom", sbom),
                           ("receipt", json.dumps(receipt, indent=2))):
            save_proof(evidence, artifact_id, name, data)
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        with conn.transaction():
            inserted = conn.execute("INSERT INTO hosting.artifact_admissions "
                                    "(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                                    "VALUES (%s,%s,%s,%s,%s::jsonb) ON CONFLICT(image) DO NOTHING RETURNING image",
                                    (args.image, receipt["sbom_sha256"], args.source_commit,
                                     args.policy_revision, json.dumps(receipt))).fetchone()
            if not inserted:
                row = conn.execute("SELECT source_commit,policy_revision,sbom_sha256,verification_receipt "
                                   "FROM hosting.artifact_admissions WHERE image=%s", (args.image,)).fetchone()
                if not row or (row[0], row[1], row[2], row[3]) != (args.source_commit, args.policy_revision,
                                                                 receipt["sbom_sha256"], receipt):
                    raise RuntimeError("Concurrent admission differs from local evidence")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
