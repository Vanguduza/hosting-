#!/usr/bin/env python3
"""Trusted-source build → push → digest → sign → scan/SBOM/admit pipeline."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def run(args, *, cwd=None, timeout=3600):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed with exit {result.returncode}")
    return result.stdout.strip()


def image_digest(metadata, name):
    digest = metadata.get("containerimage.digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise RuntimeError("Build did not return an immutable OCI digest")
    return name + "@" + digest


def rootless_builder(builder):
    if os.geteuid() == 0:
        raise RuntimeError("Builds must run as a non-root user on a dedicated build host")
    info = json.loads(run(["docker", "info", "--format", "{{json .SecurityOptions}}"], timeout=20))
    if not any("rootless" in option for option in info):
        raise RuntimeError("Rootless Docker Engine is required")
    details = run(["docker", "buildx", "inspect", "--builder", builder], timeout=30)
    if not re.search(r"(?im)^Driver:\s+docker-container\s*$", details):
        raise RuntimeError("The named Buildx builder must use the docker-container driver")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--image", required=True, help="Registry and repository without a tag")
    parser.add_argument("--builder", required=True)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--cosign-public-key", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--policy-revision", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        parser.error("commit must be a full Git SHA-1")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}", args.image) or ":" in args.image.rsplit("/", 1)[-1]:
        parser.error("image must be a registry repository without a mutable tag")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.builder):
        parser.error("invalid builder name")
    source = args.source.resolve(strict=True)
    submitted_file = source / args.dockerfile
    dockerfile = submitted_file.resolve(strict=True)
    if not dockerfile.is_relative_to(source) or not dockerfile.is_file() or submitted_file.is_symlink():
        parser.error("Dockerfile must be a regular file inside the source checkout")
    if run(["git", "rev-parse", "HEAD"], cwd=source, timeout=20) != args.commit:
        raise RuntimeError("Checkout does not match the requested immutable commit")
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, timeout=20):
        raise RuntimeError("Source checkout is dirty")
    if not args.signing_key.is_file() or not args.cosign_public_key.is_file():
        raise RuntimeError("Dedicated signing and verification keys are required")
    rootless_builder(args.builder)
    tag = args.image + ":" + args.commit
    with tempfile.TemporaryDirectory(prefix="dial-build-") as temp:
        meta = Path(temp) / "metadata.json"
        run(["docker", "buildx", "build", "--builder", args.builder,
             "--file", str(dockerfile), "--push", "--provenance=mode=max", "--sbom=true",
             "--metadata-file", str(meta), "--tag", tag, str(source)])
        immutable = image_digest(json.loads(meta.read_text()), args.image)
        run(["cosign", "sign", "--yes", "--key", str(args.signing_key), immutable], timeout=300)
        command = [sys.executable, str(Path(__file__).with_name("admit_image.py")),
                   "--image", immutable, "--source-commit", args.commit,
                   "--policy-revision", args.policy_revision,
                   "--cosign-public-key", str(args.cosign_public_key),
                   "--evidence-dir", str(args.evidence_dir)]
        receipt = run(command)
        print(receipt)


if __name__ == "__main__":
    main()
