"""Trusted publisher receipts; no business decisions or provisioning operations."""
import json
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from psycopg.types.json import Jsonb

CONTRACTS = Path(__file__).parent / 'contracts'
SOURCE_SCHEMA = json.loads((CONTRACTS/'partner-authority-source-v1.schema.json').read_text())
RECEIPT_SCHEMA = json.loads((CONTRACTS/'partner-authority-receipt-v1.schema.json').read_text())


def validate(value, source=False):
    schema = SOURCE_SCHEMA if source else RECEIPT_SCHEMA
    if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(value):
        raise ValueError('Invalid Partner authority contract')
    integer = 'max_validity_seconds' if source else 'sequence'
    if type(value[integer]) is not int:
        raise ValueError('Integer required')
    # Match PostgreSQL UTF-8 JSON canonicalization and reject lone surrogates.
    json.dumps(value, ensure_ascii=False).encode('utf-8')
    if not source:
        if len({item['ref'] for item in value['admin_bindings']}) != len(value['admin_bindings']):
            raise ValueError('Unique administrator references required')
        if value['valid_until'] is not None and datetime.fromisoformat(value['valid_until']) <= datetime.fromisoformat(value['issued_at']):
            raise ValueError('Expiry must follow issuance')
    return value


def handle(conn, org, app, intent, body, method):
    if method == 'GET':
        result = conn.execute('SELECT hosting.partner_authority_readback(%s,%s,%s) AS result', (org,app,intent)).fetchone()['result']
        return (200, result) if result else (404, {'error':'not_found'})
    if method != 'POST' or set(body) != {'receipt'}:
        return 400, {'error':'invalid_authority_receipt'}
    try:
        validate(body['receipt'])
    except (ValueError,TypeError,UnicodeError):
        return 400, {'error':'invalid_authority_receipt'}
    result = conn.execute('SELECT hosting.publish_partner_authority(%s,%s,%s,%s) AS result',
                          (org,app,intent,Jsonb(body['receipt']))).fetchone()['result']
    if not result: return 404, {'error':'not_found'}
    return (200 if result['replayed'] else 201), result
