# Tool 2 - YARA Memory Scanner 

## Purpose
Scan memory dumps for known malicious indicators using YARA rules. Designed specifically for detecting credential theft tools, fileless Powershell execution, and process injection techniques.

## Key features
- Built-in rules tailored to this project
- Support for external rule files
- Rich output with rule descriptions and offsets

## Dependencies
- Python 3
- yara-python (`pip install yara-python`)

## Usage Examples
```bash
./yara_scanner.py <path_to_memory_dump.raw>
# or
python3 yara_scanner.py <path_to_memory_dump.raw>

# Scan with built-in rules
./yara_scanner.py /home/kali/HD/MemoryDumps/credential_theft_ftk.raw

# Scan with external rules
./yara_scanner.py /home/kali/HD/MemoryDumps/fileless_malware_ftk.raw -r rules/custom_rules.yar
```