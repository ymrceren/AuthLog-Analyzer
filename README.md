# AuthLog Analyzer

A lightweight Python command-line tool for analyzing
Linux authentication logs and identifying repeated
failed login attempts.

## Features

- Parses common Linux SSH authentication log entries
- Counts failed authentication events by source IP
- Flags IP addresses exceeding a configurable threshold
- Exports findings to JSON
- Uses Python's standard library

## Technologies

- Python
- Regular Expressions
- Linux Authentication Logs
- JSON

## Usage

```bash
python authlog_analyzer.py --file sample_auth.log --threshold 3