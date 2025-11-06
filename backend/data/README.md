# IP Address Data Files

Place your malicious and legitimate IP address data files in this directory.

## Supported File Formats

### CSV Format
- File names: `malicious_ips.csv` or `legitimate_ips.csv`
- Format: CSV with an `ip` column, or one IP per line
- Example:
```csv
ip
192.0.2.1
203.0.113.1
100.38.210.187
```

### Text Format
- File names: `malicious_ips.txt` or `legitimate_ips.txt`
- Format: One IP address per line
- Example:
```
192.0.2.1
203.0.113.1
100.38.210.187
```

### JSON Format
- File names: `malicious_ips.json` or `legitimate_ips.json`
- Format: Array of IPs or object with `ips` key
- Example:
```json
["192.0.2.1", "203.0.113.1", "100.38.210.187"]
```
or
```json
{
  "ips": ["192.0.2.1", "203.0.113.1", "100.38.210.187"]
}
```

## Notes
- IP addresses can be exact IPs (e.g., `192.0.2.1`) or ranges (e.g., `185.220.100.0`)
- Comments in text files start with `#`
- The system will automatically detect and load the appropriate file format

