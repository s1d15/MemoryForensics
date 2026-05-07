#!/usr/bin/env python3
"""
Memory Triage Summary Tool
Purpose: Automated triage of memory dumps using Volatility 3
"""

import sys
import subprocess
import os
import argparse
from datetime import datetime
from zoneinfo import ZoneInfo

def run_volatility(plugin, dump_path, timeout=90):

    # Run Volatility 3 plugin and return output
    try:
        cmd = [
            'python3',
            'vol.py',
            '-q',
            '-f',
            dump_path,
            f'windows.{plugin}'
        ]
        
        result = subprocess.check_output(cmd, cwd='/home/kali/HD/volatility3', text=True, timeout=timeout, stderr=subprocess.STDOUT)
        
        return result.strip()
    
    except subprocess.TimeoutExpired:
        return f'[TIMEOUT] Plugin {plugin} took too long to execute'
    
    except Exception as e:
        return f'[ERROR] {plugin}: {str(e)}'
    
def main():
    parser = argparse.ArgumentParser(description='Memory Forensics Triage Tool')
    parser.add_argument('dump', help='Path to memory dump file')
    parser.add_argument('-o', '--output', default=None, help='Output report file (HTML)')
    args = parser.parse_args()

    dump_path = args.dump
    if not os.path.exists(dump_path):
        print(f'Error: File {dump_path} not found!')
        sys.exit(1)
    
    timestamp = datetime.now(ZoneInfo('Australia/Melbourne')).strftime("%d-%m-%Y %H:%M:%S %Z")

    print(f'=== MEMORY TRIAGE SUMMARY REPORT ===')
    print(f'Generated: {timestamp}')
    print(f'Dump file: {dump_path}\n')

    plugins = {
        'info'   : 'System Information',
        'pslist' : 'Running Processes',
        'psscan' : 'Hidden/Active Processes',
        'netscan': 'Network Connections',
        'cmdline': 'Process Command Lines',
        'malfind': 'Injected Code Detection',
    }

    report = f'<h1>Memory Triage Report - {timestamp}</h1>\n'

    for plugin, title in plugins.items():
        print(f'\n[+] Running {title}...')
        output = run_volatility(plugin, dump_path)

        # Truncate very long outputs for console
        console_output = output[:1200] + "..." if len(output) > 1200 else output

        print(f'   {title} complete.')
        print(console_output[:500]) # Print preview

        # Add to HTML report
        report += f'<h2>{title}</h2><pre>{output}</pre>\n'

    if args.output:
        html_file = args.output
    else:
        html_file = f'triage_report_{os.path.basename(dump_path)}.html'

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(f'<html><body>{report}</body></html>')

    print(f'Full report saved to: {html_file}')

if __name__ == '__main__':
    main()