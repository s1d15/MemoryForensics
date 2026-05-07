# Tool 1 - Memory Triage Summary

## Purpose
This script performs automated triage on Windows memory dumps by running key Volatiltiy 3 plugins. It helps investigators quickly understand what was running on the system at the time of acquisision.

## Key features
- Runs 6 important Volatility plugins
- Generates clean HTML report
- Erorr handling and timeout protection
- Console + file output

## Dependencies
- Python 3
- Volatility 3
- Run from the Volatility 3 directory

## Usage Examples
```bash
./triage_summary.py <path_to_memory_dump.raw>
# or 
python3 triage_summary.py <path_to_memory_dump.raw>

# Basic Usage
./triage_summary.py /home/kali/HD/MemoryDumps/real_time_atack_ftk.raw

# With custom output name
./triage_summary.py /home/kali/HD/MemoryDumps/fileless_malware_ftk.raw -o fileless_triage.html
```

