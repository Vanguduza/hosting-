#!/usr/bin/env python3
"""Durable, isolated GitHub push builder for explicitly registered trusted source."""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.migrate import verify as verify_schema


def run(args, *, timeout=300, cwd=None):
    process = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                             check=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if process.returncode:
        raise RuntimeError("Build step failed: " + Path(args[0]).name)
    return process.stdout.strip()


def claim(conn):
    with conn.transaction():
        # A process can die during its final attempt. Expire its lease instead
        # of leaving a permanent RUNNING row that no worker can ever claim.
        conn.execute("UPDATE hosting.github_builds SET state='FAILED',lease_until=NULL,"
                     "last_error='Worker lease expired' WHERE state='RUNNING' AND "
                     "attempts=3 AND lease_until<now()")
        row = conn.execute("SELECT delivery_id,source_id,source_commit,attempts "
                           "FROM hosting.github_builds WHERE attempts<3 AND "
                           "((state='QUEUED' AND next_attempt_at<=now()) OR "
                           "(state='RUNNING' AND lease_until<now())) "
                           "ORDER BY next_attempt_at,delivery_id FOR UPDATE SKIP LOCKED LIMIT 1").fetchone()
        if not row:
            return None
        source = conn.execute("SELECT * FROM hosting.git_sources WHERE id=%s", (row["source_id"],)).fetchone()
        attempt = row["attempts"] + 1
        conn.execute("UPDATE hosting.github_builds SET state='RUNNING',attempts=%s,"
                     "lease_until=now()+interval '90 minutes' WHERE delivery_id=%s", (attempt, row["delivery_id"]))
        return row, source, attempt


def checkout(source, commit, destination):
    full_name = source["full_name"]
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name) or
            not re.fullmatch(r"[a-f0-9]{40}", commit) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}", source["branch"])):
        raise ValueError("Registered source or commit invalid")
    url = "https://github.com/" + full_name + ".git"
    run(["git", "-c", "protocol.file.allow=never", "clone", "--no-checkout", "--single-branch",
         "--branch", source["branch"], "--filter=blob:none", "--depth", "1", url, str(destination)], timeout=300)
    if run(["git", "rev-parse", "HEAD"], cwd=destination, timeout=20) != commit:
        run(["git", "fetch", "--depth", "1", "origin", commit], cwd=destination, timeout=120)
    run(["git", "checkout", "--detach", commit], cwd=destination, timeout=120)
    if run(["git", "rev-parse", "HEAD"], cwd=destination, timeout=20) != commit or \
            run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=destination, timeout=20):
        raise RuntimeError("Trusted checkout differs from delivery commit")


def build(source, commit, settings):
    if not source or not source["enabled"]:
        raise RuntimeError("Registered source disabled")
    with tempfile.TemporaryDirectory(prefix="dial-github-build-") as temporary:
        destination = Path(temporary) / "source"
        checkout(source, commit, destination)
        command = [sys.executable, str(Path(__file__).with_name("build_release.py")),
                   "--source", str(destination), "--commit", commit,
                   "--dockerfile", source["dockerfile"], "--image", source["image_repository"],
                   "--builder", source["builder"], "--signing-key", settings["signing_key"],
                   "--cosign-public-key", settings["public_key"], "--evidence-dir", settings["evidence_dir"],
                   "--policy-revision", source["policy_revision"]]
        output = run(command, timeout=3900)
        receipt = json.loads(output.splitlines()[-1])
        if (receipt.get("source_commit") != commit or receipt.get("policy_revision") != source["policy_revision"] or
                not re.fullmatch(re.escape(source["image_repository"]) + r"@sha256:[a-f0-9]{64}",
                                 receipt.get("image", ""))):
            raise RuntimeError("Build admission receipt differs from source")
        return receipt


def finalize(conn, job, source, attempt, receipt=None, failure=None):
    with conn.transaction():
        current = conn.execute("SELECT state,attempts FROM hosting.github_builds WHERE delivery_id=%s FOR UPDATE",
                               (job["delivery_id"],)).fetchone()
        if not current or current["state"] != "RUNNING" or current["attempts"] != attempt:
            return False
        if receipt:
            admitted = conn.execute("SELECT source_commit,policy_revision,verification_receipt "
                                    "FROM hosting.artifact_admissions WHERE image=%s",
                                    (receipt["image"],)).fetchone()
            if (not admitted or admitted["source_commit"] != job["source_commit"] or
                    admitted["policy_revision"] != source["policy_revision"] or
                    admitted["verification_receipt"] != receipt):
                raise RuntimeError("Authoritative admission proof differs")
            conn.execute("UPDATE hosting.github_builds SET state='ADMITTED',lease_until=NULL,image=%s "
                         "WHERE delivery_id=%s", (receipt["image"], job["delivery_id"]))
        elif attempt < 3:
            conn.execute("UPDATE hosting.github_builds SET state='QUEUED',lease_until=NULL,last_error=%s,"
                         "next_attempt_at=now()+(%s*interval '1 second') WHERE delivery_id=%s",
                         (str(failure)[:80], attempt * 30, job["delivery_id"]))
        else:
            conn.execute("UPDATE hosting.github_builds SET state='FAILED',lease_until=NULL,last_error=%s "
                         "WHERE delivery_id=%s", (str(failure)[:80], job["delivery_id"]))
        return True


def process_once(conn, settings):
    claimed = claim(conn)
    if not claimed:
        return False
    job, source, attempt = claimed
    try:
        receipt = build(source, job["source_commit"], settings)
        finalize(conn, job, source, attempt, receipt=receipt)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, psycopg.Error) as exc:
        finalize(conn, job, source, attempt, failure=type(exc).__name__)
    return True


def main():
    if os.geteuid() == 0:
        raise RuntimeError("GitHub build worker must run as a non-root identity")
    names = ("HOSTING_BUILD_DSN", "HOSTING_ADMISSION_DSN", "BUILDER_SIGNING_KEY",
             "BUILDER_COSIGN_PUBLIC_KEY", "BUILDER_EVIDENCE_DIR")
    if any(not os.environ.get(name) for name in names):
        raise RuntimeError("Missing isolated builder configuration")
    settings = {"signing_key": os.environ["BUILDER_SIGNING_KEY"],
                "public_key": os.environ["BUILDER_COSIGN_PUBLIC_KEY"],
                "evidence_dir": os.environ["BUILDER_EVIDENCE_DIR"]}
    for name in ("signing_key", "public_key"):
        path = Path(settings[name])
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("Builder key file unavailable or unsafe")
    with psycopg.connect(os.environ["HOSTING_BUILD_DSN"], connect_timeout=5) as conn:
        if conn.execute("SELECT current_user").fetchone()[0] != "hosting_buildworker":
            raise RuntimeError("Builder requires the restricted buildworker role")
        verify_schema(conn)
    while True:
        try:
            with psycopg.connect(os.environ["HOSTING_BUILD_DSN"], row_factory=dict_row,
                                 connect_timeout=5, autocommit=True) as conn:
                did_work = process_once(conn, settings)
            if not did_work:
                time.sleep(2)
        except psycopg.Error:
            time.sleep(5)


if __name__ == "__main__":
    main()
