import pytest
from guardianeye.core.scanner import MaliciousFileScanner

def test_clean_file_scan(clean_file):
    """Test scanning a clean file."""
    scanner = MaliciousFileScanner()
    result = scanner.scan_file(str(clean_file))
    assert result['status'] == 'clean'
    assert result['error'] is None

def test_malicious_file_scan(malicious_file):
    """Test scanning a malicious file (EICAR test file)."""
    scanner = MaliciousFileScanner()
    result = scanner.scan_file(str(malicious_file))
    assert result['status'] == 'malicious'
    assert result['error'] is None
    assert result['threat_info']['name'] == 'EICAR-TEST-FILE'
    assert result['threat_info']['severity'] == 'High' 