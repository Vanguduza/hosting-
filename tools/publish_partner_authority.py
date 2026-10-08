#!/usr/bin/env python3
"""Publish an existing Partner decision using its registered service identity."""
import argparse
import json

from hosting_cli import call, identifier, private_file
from partner_authority_source import private_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    parser.add_argument('--token-file',required=True)
    parser.add_argument('--ca-file')
    parser.add_argument('--org',required=True)
    parser.add_argument('--app',required=True)
    parser.add_argument('--intent-id',required=True)
    parser.add_argument('--receipt-file',required=True)
    args=parser.parse_args()
    path='/v1/organizations/'+identifier(args.org)+'/applications/'+identifier(args.app)+'/intents/'+identifier(args.intent_id)+'/authority'
    try:
        receipt=private_json(args.receipt_file,source=False)
        status,result=call(args.url,path,private_file(args.token_file,'Publisher token'),{'receipt':receipt},args.ca_file)
        print(json.dumps({'status':status,**result}))
        if status>=400: raise SystemExit(1)
    except (ValueError,OSError):
        raise SystemExit('Authority publication failed; check the private input and trusted endpoint')


if __name__=='__main__': main()
