import pytest
import os
from pathlib import Path

@pytest.fixture
def test_files_dir():
    """Return the path to test files directory."""
    return Path(__file__).parent / "test_files"

@pytest.fixture
def clean_file(test_files_dir):
    """Return the path to clean test file."""
    return test_files_dir / "clean_file.txt"

@pytest.fixture
def malicious_file(test_files_dir):
    """Return the path to malicious test file."""
    return test_files_dir / "malicious_file.txt" 