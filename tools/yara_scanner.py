#!/usr/bin/env python3
"""
YARA Memory Scanner Tool
Purpose: Scan memory dumps for malicious patterns using custom YARA rules
"""

import yara
import sys
import os
import argparse
from datetime import datetime
from zoneinfo import ZoneInfo

YARA_RULES = """
rule Credential_Theft_Indicators {
    meta:
        description = "Detects credential dumping tools and strings"
    strings:
        $m1 = "lsass" nocase
        $m2 = "mimikatz" nocase
        $m3 = "sekurlsa" nocase
        $m4 = "procdump" nocase
    condition: 2 of them
}

rule Fileless_Powershell {
    meta:
        description = "Detect fileless Powershell execution"
    strings:
        $p1 = "IEX(" nocase
        $p2 = "DownloadString" nocase
        $p3 = "Invoke-WebRequest" nocase
        $p4 = "-ep bypass" nocase
    condition: 2 of them
}

rule Process_Injection {
    meta:
        description = "Detects common process injection patterns"
    strings:
        $i1 = "VirtualAlloc" nocase
        $i2 = "WriteProcessMemory" nocase
        $i3 = "CreateRemoteThread" nocase
    condition: 2 of them
}
"""

def main():
    parser = argparse.ArgumentParser(description='YARA Memory Scanner')
    parser.add_argument('dump', help='Path to memory dump')
    parser.add_argument('-r', '--rules', default=None, help='Path to external .yar file')
    args = parser.parse_args()

    dump_path = args.dump
    if not os.path.exists(dump_path):
        print(f'Error: Dump file not found: {dump_path}')
        sys.exit(1)

    timestamp = datetime.now(ZoneInfo('Australia/Melbourne')).strftime("%d-%m-%Y %H:%M:%S %Z")

    print(f'===YARA MEMORY SCANNER ===')
    print(f'Target: {dump_path}')
    print(f'Time: {timestamp}\n')

    try:
        if args.rules and os.path.exists(args.rules):
            rules = yara.compile(filepath=args.rules)
            print(f'Loaded external rules: {args.rules}')

        else:
            rules = yara.compile(source=YARA_RULES)
            print(f'Loaded built-in rules')
            
    except Exception as e:
        print(f'Error compiling YARA rules: {e}')
        sys.exit(1)
    
    print("Scanning memory dump...")
    matches = rules.match(dump_path)

    if matches:
        print(f'\n {len(matches)} YARA RULE(S) MATCHED!\n')

        for match in matches:
            print(f'Rule: {match.rule}')

            if match.meta:
                print(f'Description: {match.meta.get('description', 'N/A')}')

            for yara_string in match.strings:
                print(f'String ID: {yara_string.identifier} = {yara_string.instances[0]}')

                for instance in yara_string.instances:
                    print(f'\t- {hex(instance.offset)}')
                
                print()
            
            print('-' * 60)
    
    else:
        print(f'\nYARA scan completed.')

if __name__ == '__main__':
    main()