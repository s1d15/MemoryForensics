# Custom Forensics Tool
**Project:** Memory and Volatile Data Forensics
**Author:** Nhat Nguyen
**Purpose:** Custom tools developed to support real-time attack detection, credential theft, and fileless malware analysis.

## Dependencies
All included dependencies can be installed using `requirements.txt` using the command:
```bash
pip install -r requirements.txt
```

## Tools Overview
### Tool 1: Memory Triage Summary (`triage_summary.py`)
**Description**
This tool automate the intial triage of a Windows memory dump by executing multiple key Volatility 3 plugins. It provides a quick, investigator-friendly overview of the system state, helping to rapidly identify suspicious processes, network activity, and potential code injection.

**Purpose**
- Reduce analysis time by summarizing the most important artefacts.
- Support **real-time attack detection** and general triage.
- Generate HTML reports for documentation.

**How it was used**
Executed on all captured memory dumps (Baseline + 3 scenarios) after transferring them to Kali Linux. The generated HTML were included as supporting evidence in the project.

**Dependencies**
- Python 3.8+
- Volatility 3 Framework
- subprocess, argparse, datetime (standard library)

**Configuration / Customization:**
- Default timeout of 90 seconds per plugin to prevent hanging on large dumps.
- HTML report generation for better readability.
- Silent mode (`-q`) used to reduce console noise.

**Usage:**
```bash
./triage_summary.py <path_to_memory_dump.raw>
# or 
python3 triage_summary.py <path_to_memory_dump.raw>

Example:
./triage_summary.py credential_theft_ftk -o triage_credential_report.html
```

### Tool 2: YARA Memory Scanner (`yara_scanner.py`)
**Description**
A python wrapper around YARA that scans memory dumps for malicious patterns using custom rules tailored to this project.

**Purpose**
- Detect signatures related to **credential theft**, **fileless malware**, and **process injection**.

**How it was used**
Ran against every memory dump (especially Fileless Malware and Theft scenarios) to identify malcious strings and code patterns.

**Dependencies**
- Python 3.8+
- `yara-python` library (`pip install yara-python`)

**Configuration / Customization:**
- Embedded custom YARA rules specifically designed for the three project scenarios.
- Support external `.yar` rule files via command-line argument.
- Detailed output including rule metadata

**Usage:**
```bash
./yara_scanner.py <path_to_memory_dump.raw>
# or
python3 yara_scanner.py <path_to_memory_dump.raw>

# Example:
./yara_scanner.py fileless_malware_ftk.raw -r my_custom_rules.yar
```