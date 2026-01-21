# Winreg

## Overview
**Winreg** is a Windows Event Log extractor built for forensic analysis.  
It provides a graphical interface to identify Windows Event Log file locations from the Windows Registry and export selected logs using native Windows utilities.

The tool is designed to assist digital forensics and incident response by simplifying the collection of critical Windows Event Logs.

## How It Works
Winreg performs the following steps:
1. Reads Windows Registry keys related to Event Logging
2. Extracts the physical `.evtx` file paths stored in the registry
3. Resolves `%SystemRoot%` to the actual Windows directory
4. Uses `wevtutil` to export selected event logs
5. Saves registry-derived log paths and exported logs to a user-defined directory

## Supported Event Logs
- Application
- System
- Security
- Setup
- Forwarded Events

## Features
- GUI-based log selection using Tkinter
- Registry-based extraction of event log file paths
- Automatic environment variable resolution
- Exports logs in native `.evtx` format
- Generates a summary report (`logging_info.txt`)
- Uses built-in Windows tools (no external dependencies)

## Requirements
- **Operating System:** Windows
- **Python Version:** 3.x
- **Permissions:** Administrator privileges recommended
- **Dependencies:**
  - `tkinter` (included with standard Python on Windows)
  - `winreg`
  - `subprocess`
  - `wevtutil` (native Windows utility)

## Installation
```bash
git clone https://github.com/yourusername/Winreg.git
cd Winreg
```
## Usage

Run the script with administrative privileges:
```bash
python winreg.py

