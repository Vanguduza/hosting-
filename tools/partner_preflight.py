#!/usr/bin/env python3
"""Validate partner desired state and read existing hosting evidence. Never writes."""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError

from jsonschema import Draft202012Validator

from hosting_cli import call, identifier, private_file

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "contracts/hosting-intent-v1.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def validate(intent):
    # Report field names, never rejected values (which can contain credentials).
    errors = sorted({"/" + "/".join(str(part) for part in error.absolute_path)
                     for error in VALIDATOR.iter_errors(intent)})
    if errors:
        raise ValueError("Invalid HostingIntent fields: " + ", ".join(errors))
    if any(type(value) is not int for value in intent["resource_budget"].values()):
        raise ValueError("Invalid HostingIntent fields: /resource_budget")
    if intent["domain_intent"]["hostname"].endswith((".local", ".internal")):
        raise ValueError("Invalid HostingIntent fields: /domain_intent/hostname")
    canonical = json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def preflight(intent, organization, application, read=None, now=None):
    digest = validate(intent)
    identifier(organization)
    identifier(application)
    now = now or datetime.now(timezone.utc)
    stages = []

    def stage(name, state, reason):
        stages.append({"stage": name, "state": state, "reason": reason})

    stage("intake", "VALIDATED", "Typed v1 desired state; no fields transformed")
    stage("commercial_authority", "BLOCKED", "Canonical partner/tenant/entitlement binding is not installed")
    stage("profile_qualification", "BLOCKED", "No qualified profile registry or estate certificate is installed")
    if intent["database_profile"] == "supabase-unqualified":
        stage("database_profile", "BLOCKED", "Managed Supabase is not implemented")
    if intent["storage_profile"] == "s3-redundant-unqualified" or (
            intent["storage_profile"] == "garage-development-v1" and intent["environment_profile"] != "development"):
        stage("storage_profile", "BLOCKED", "This storage profile cannot satisfy the requested environment")
    stage("secret_bindings", "BLOCKED" if intent["secret_refs"] else "NOT_REQUESTED",
          "No Partner secret-reference resolver is installed" if intent["secret_refs"] else "No secret references requested")
    stage("tenant_admin_bindings", "BLOCKED", "Administrative references require canonical subject/tenant resolution")
    stage("backups", "BLOCKED", "Independent backup/restore receipts are not exposed through the tenant API")
    if read is None:
        stage("live_readback", "NOT_OBSERVED", "No authenticated control API readback requested")
    else:
        org = "/v1/organizations/" + organization
        app = org + "/applications/" + application

        def get(path):
            status, body = read(path)
            if status != 200 or not isinstance(body, dict):
                raise ValueError("Authenticated hosting readback unavailable")
            return body

        applications = get(org + "/projects/" + intent["project_id"] + "/applications")["applications"]
        matches = [row for row in applications if row["id"] == application]
        if len(matches) != 1 or matches[0]["environment"] != intent["environment_profile"]:
            stage("tenant_project_environment", "BLOCKED", "Application is absent or environment differs")
        else:
            stage("tenant_project_environment", "MATCHED", "Authenticated project application and environment match")
            releases = get(app + "/releases")["releases"]
            health = get(app + "/health")
            selected = [row for row in releases if row["id"] == health.get("release_id")]
            bound = len(selected) == 1 and selected[0]["image"] == intent["release_artifact_ref"] and selected[0]["state"] == "SERVING"
            stage("artifact_runtime", "MATCHED" if bound else "BLOCKED",
                  "Active serving release has the requested immutable artifact" if bound else "Requested artifact is not the active serving release")
            checked = None
            try:
                checked = datetime.fromisoformat(health["checked_at"].replace("Z", "+00:00"))
                fresh = checked.tzinfo is not None and now - timedelta(minutes=3) <= checked <= now
            except (KeyError, TypeError, AttributeError, ValueError):
                fresh = False
            healthy = bound and fresh and health.get("state") == "UP"
            stage("release_health", "OBSERVED_HEALTHY" if healthy else "BLOCKED",
                  "Fresh health observation is bound to the requested serving release" if healthy else "Fresh release-bound health evidence is missing")
            domain = get(app + "/domain").get("domain")
            matched = isinstance(domain, dict) and domain.get("hostname") == intent["domain_intent"]["hostname"] and bool(domain.get("verified_at"))
            stage("domain_ownership", "MATCHED" if matched else "BLOCKED",
                  "Requested hostname has tenant ownership proof" if matched else "Requested hostname lacks matching ownership proof")
            for resource, profile in (("postgres", "database_profile"), ("storage", "storage_profile")):
                body = get(app + "/" + resource)
                key = "postgres" if resource == "postgres" else "storage"
                if key not in body:
                    raise ValueError("Resource readback malformed")
                row = body[key]
                desired = intent[profile] != "none"
                matched = (isinstance(row, dict) and row.get("state") == "READY") if desired else row is None
                stage(resource, "MATCHED" if matched else "BLOCKED",
                      "Private resource readback matches presence intent" if matched else "Private resource state differs from intent")
            stage("resource_budget", "NOT_OBSERVED", "Release readback omits its CPU/memory allocation; no budget proof inferred")
    return {"schema_version": "1.0", "request_id": intent["request_id"], "intent_sha256": digest,
            "state": "NOT_QUALIFIED", "mutations_performed": False, "transformations": [], "stages": stages}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("intent", type=Path)
    parser.add_argument("--organization", required=True, type=identifier)
    parser.add_argument("--application", required=True, type=identifier)
    parser.add_argument("--base-url")
    parser.add_argument("--token-file")
    parser.add_argument("--ca-file")
    args = parser.parse_args(argv)
    try:
        with args.intent.open(encoding="utf-8") as stream:
            raw = stream.read(65537)
        if len(raw.encode()) > 65536:
            raise ValueError("Intent exceeds 64 KiB")
        intent = json.loads(raw, object_pairs_hook=unique_object)
        validate(intent)  # Reject before network access or token loading.
        read = None
        if args.base_url:
            if not args.token_file:
                raise ValueError("Token file required for authenticated readback")
            token = private_file(args.token_file, "Control API token")
            read = lambda path: call(args.base_url, path, token, ca_file=args.ca_file)
        elif args.token_file or args.ca_file:
            raise ValueError("Base URL required for readback configuration")
        print(json.dumps(preflight(intent, args.organization, args.application, read), sort_keys=True))
        return 1  # A valid request remains unqualified, including healthy readback.
    except (ValueError, OSError, URLError, KeyError, TypeError):
        print(json.dumps({"error": "partner_preflight_failed"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
