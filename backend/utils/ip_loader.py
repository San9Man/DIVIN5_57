"""
IP Address Data Loader
Loads malicious and legitimate IP addresses from data files.
Supports CSV, JSON, and plain text formats.
"""

import os
import csv
import json
from pathlib import Path

# Default paths for IP data files
DATA_DIR = Path(__file__).parent.parent / "data"
MALICIOUS_IPS_FILE = DATA_DIR / "malicious_ips.csv"
LEGITIMATE_IPS_FILE = DATA_DIR / "legitimate_ips.csv"

# In-memory cache for loaded IPs
_malicious_ips_cache = None
_legitimate_ips_cache = None


def load_ips_from_csv(file_path):
    """
    Load IP addresses from a CSV file.
    Expected format: CSV with 'ip' column, or one IP per line.
    """
    ips = []
    if not os.path.exists(file_path):
        return ips
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Try to detect if it has headers
            sample = f.read(1024)
            f.seek(0)
            
            # Check if first line looks like a header
            first_line = f.readline().strip()
            f.seek(0)
            
            reader = csv.reader(f)
            
            # Skip header if it exists
            if first_line and ('ip' in first_line.lower() or 'address' in first_line.lower()):
                next(reader)
            
            for row in reader:
                if row:
                    # Get first column or first non-empty value
                    ip = row[0].strip() if row[0] else (row[1].strip() if len(row) > 1 and row[1] else None)
                    if ip and _is_valid_ip(ip):
                        ips.append(ip)
    except Exception as e:
        print(f"Error loading CSV file {file_path}: {e}")
    
    return ips


def load_ips_from_txt(file_path):
    """
    Load IP addresses from a plain text file (one IP per line).
    """
    ips = []
    if not os.path.exists(file_path):
        return ips
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                ip = line.strip()
                # Skip comments and empty lines
                if ip and not ip.startswith('#') and _is_valid_ip(ip):
                    ips.append(ip)
    except Exception as e:
        print(f"Error loading text file {file_path}: {e}")
    
    return ips


def load_ips_from_json(file_path):
    """
    Load IP addresses from a JSON file.
    Expected format: {"ips": ["1.2.3.4", ...]} or ["1.2.3.4", ...]
    """
    ips = []
    if not os.path.exists(file_path):
        return ips
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            if isinstance(data, list):
                ips = [ip for ip in data if _is_valid_ip(str(ip))]
            elif isinstance(data, dict):
                # Try common keys
                for key in ['ips', 'ip_addresses', 'addresses', 'data']:
                    if key in data and isinstance(data[key], list):
                        ips = [ip for ip in data[key] if _is_valid_ip(str(ip))]
                        break
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {e}")
    
    return ips


def _is_valid_ip(ip):
    """Basic validation for IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def load_malicious_ips():
    """
    Load malicious IP addresses from data files.
    Returns a list of IP addresses.
    """
    global _malicious_ips_cache
    
    if _malicious_ips_cache is not None:
        return _malicious_ips_cache
    
    ips = []
    
    # Try different file formats
    for file_path in [
        MALICIOUS_IPS_FILE,
        DATA_DIR / "malicious_ips.txt",
        DATA_DIR / "malicious_ips.json",
    ]:
        if os.path.exists(file_path):
            if file_path.suffix == '.csv':
                ips = load_ips_from_csv(file_path)
            elif file_path.suffix == '.json':
                ips = load_ips_from_json(file_path)
            else:
                ips = load_ips_from_txt(file_path)
            
            if ips:
                print(f"Loaded {len(ips)} malicious IPs from {file_path}")
                break
    
    _malicious_ips_cache = ips
    return ips


def load_legitimate_ips():
    """
    Load legitimate IP addresses from data files.
    Returns a list of IP addresses.
    """
    global _legitimate_ips_cache
    
    if _legitimate_ips_cache is not None:
        return _legitimate_ips_cache
    
    ips = []
    
    # Try different file formats
    for file_path in [
        LEGITIMATE_IPS_FILE,
        DATA_DIR / "legitimate_ips.txt",
        DATA_DIR / "legitimate_ips.json",
    ]:
        if os.path.exists(file_path):
            if file_path.suffix == '.csv':
                ips = load_ips_from_csv(file_path)
            elif file_path.suffix == '.json':
                ips = load_ips_from_json(file_path)
            else:
                ips = load_ips_from_txt(file_path)
            
            if ips:
                print(f"Loaded {len(ips)} legitimate IPs from {file_path}")
                break
    
    _legitimate_ips_cache = ips
    return ips


def reload_ip_lists():
    """Force reload of IP lists from files (clears cache)."""
    global _malicious_ips_cache, _legitimate_ips_cache
    _malicious_ips_cache = None
    _legitimate_ips_cache = None
    load_malicious_ips()
    load_legitimate_ips()

