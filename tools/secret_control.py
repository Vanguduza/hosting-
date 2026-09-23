#!/usr/bin/env python3
"""Provision and rotate a resource secret from protected stdin; never echo it."""
import argparse
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "api")))
from hosting_api.secrets import OpenBao


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("resource_id", type=uuid.UUID)
    parser.add_argument("--cas", type=int, required=True,
                        help="0 creates once; the current version is required for rotation")
    args = parser.parse_args()
    if os.isatty(0):
        parser.error("Provide a JSON object of secret values on stdin")
    body = sys.stdin.buffer.read(65537)
    if len(body) > 65536:
        parser.error("Secret payload too large")
    values = json.loads(body)
    version = OpenBao.environment().put(args.resource_id, values, args.cas)
    print(json.dumps({"resource_id": str(args.resource_id), "version": version, "state": "STORED"}))


if __name__ == "__main__":
    main()
