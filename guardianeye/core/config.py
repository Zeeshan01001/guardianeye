"""Configuration settings for GuardianEye."""
import os

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.getenv("GUARDIANEYE_VT_API_KEY")  # Get API key from environment variable
VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/file/report"

# Scanner configuration
DEFAULT_HASH_TYPE = "md5"  # Changed to md5 to match our signature database
SCAN_BATCH_SIZE = 1000
MAX_THREADS = 12
CHUNK_SIZE = 16 * 1024 * 1024  # 16MB chunks for memory-mapped files 