"""Shared strict HostingIntent v1 boundary; references never grant authority."""
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA = json.loads((Path(__file__).parent / 'contracts/hosting-intent-v1.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def validate(intent):
    errors = sorted({'/' + '/'.join(str(part) for part in error.absolute_path)
                     for error in VALIDATOR.iter_errors(intent)})
    if errors:
        raise ValueError('Invalid HostingIntent fields: ' + ', '.join(errors))
    if any(type(value) is not int for value in intent['resource_budget'].values()):
        raise ValueError('Invalid HostingIntent fields: /resource_budget')
    if intent['domain_intent']['hostname'].endswith(('.local', '.internal')):
        raise ValueError('Invalid HostingIntent fields: /domain_intent/hostname')
    canonical = json.dumps(intent, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
