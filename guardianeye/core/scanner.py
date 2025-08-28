#!/usr/bin/env python3

import os
import hashlib
import csv
import logging
import mmap
import threading
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Generator, Tuple
from queue import Queue
from io import DEFAULT_BUFFER_SIZE
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import yara

try:
    from guardianeye.core.config import (
        VIRUSTOTAL_API_KEY,
        VIRUSTOTAL_API_URL,
        DEFAULT_HASH_TYPE,
        SCAN_BATCH_SIZE,
        MAX_THREADS,
        CHUNK_SIZE
    )
except ImportError:
    # Default values if config.py is not found
    VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/file/report"
    DEFAULT_HASH_TYPE = "md5"
    SCAN_BATCH_SIZE = 1000
    MAX_THREADS = 12
    CHUNK_SIZE = 16 * 1024 * 1024

# Initialize rich console
console = Console()

class MalwareInfo:
    def __init__(self, name: str, severity: str, details: Optional[Dict] = None):
        self.name = name
        self.severity = severity
        self.details = details or {}

class MaliciousFileScanner:
    def __init__(self, signatures_path: str = None, hash_type: str = DEFAULT_HASH_TYPE, vt_api_key: str = None):
        self.hash_type = hash_type.lower()
        self.signatures = {}
        self.vt_api_key = vt_api_key or VIRUSTOTAL_API_KEY
        self._load_signatures(signatures_path) if signatures_path else None
        self.setup_logging()
        self.scan_queue = Queue()
        self.results = []
        self._initialize_thread_pool()
        self.vt_rate_limit = 4  # Maximum requests per minute for public API
        self.last_vt_request = 0
        self.eicar_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR MD5 hash
    
    def _initialize_thread_pool(self):
        """Initialize thread pool for parallel scanning."""
        self.thread_pool = ThreadPoolExecutor(
            max_workers=MAX_THREADS,
            thread_name_prefix="scanner"
        )
    
    def setup_logging(self):
        """Configure logging with performance optimizations."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(
                    log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                    mode='w'
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_signatures(self, signatures_path: str) -> None:
        """Load malware signatures with detailed information."""
        try:
            with open(signatures_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.signatures[row['hash']] = MalwareInfo(
                        name=row['malware_name'],
                        severity=row['severity']
                    )
            self.logger.info(f"Loaded {len(self.signatures)} signatures from {signatures_path}")
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")

    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate file hash using memory-mapped files for large files."""
        try:
            # Always use SHA256 for EICAR detection
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5(usedforsecurity=False) if self.hash_type == 'md5' else None
            
            with open(file_path, 'rb') as f:
                # Use memory mapping for large files
                if os.path.getsize(file_path) > CHUNK_SIZE:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        for chunk in iter(lambda: mm.read(CHUNK_SIZE), b''):
                            sha256_hash.update(chunk)
                            if md5_hash:
                                md5_hash.update(chunk)
                else:
                    # Use buffered reading for smaller files
                    for chunk in iter(lambda: f.read(DEFAULT_BUFFER_SIZE), b''):
                        sha256_hash.update(chunk)
                        if md5_hash:
                            md5_hash.update(chunk)
            
            # Return MD5 if requested, but check SHA256 first for EICAR
            sha256_result = sha256_hash.hexdigest()
            if sha256_result == self.eicar_hash:
                return sha256_result
            return md5_hash.hexdigest() if md5_hash else sha256_result
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return None

    def _respect_vt_rate_limit(self):
        """Respect VirusTotal API rate limits."""
        if self.last_vt_request > 0:
            elapsed = time.time() - self.last_vt_request
            if elapsed < (60 / self.vt_rate_limit):
                time.sleep((60 / self.vt_rate_limit) - elapsed)
        self.last_vt_request = time.time()

    def get_threat_info(self, file_hash: str) -> Optional[MalwareInfo]:
        """Get threat information from local database or VirusTotal."""
        # Check local database first
        if file_hash in self.signatures:
            self.logger.info(f"Found hash {file_hash} in local database")
            return self.signatures[file_hash]

        # Check VirusTotal if API key is available
        if self.vt_api_key:
            try:
                self._respect_vt_rate_limit()
                params = {
                    'apikey': self.vt_api_key,
                    'resource': file_hash
                }
                response = requests.get(VIRUSTOTAL_API_URL, params=params, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('response_code') == 1:
                        positives = result.get('positives', 0)
                        total = result.get('total', 0)
                        
                        # Determine severity based on detection ratio
                        severity = "Low"
                        if positives > 10:
                            severity = "High"
                        elif positives > 5:
                            severity = "Medium"
                        
                        self.logger.info(f"VirusTotal: {positives}/{total} detections for {file_hash}")
                        
                        return MalwareInfo(
                            name=f"Multiple Detections ({positives} engines)",
                            severity=severity,
                            details={
                                'total_engines': total,
                                'positive_detections': positives,
                                'scan_date': result.get('scan_date', ''),
                                'permalink': result.get('permalink', ''),
                                'scans': result.get('scans', {})
                            }
                        )
                elif response.status_code == 204:
                    self.logger.warning("VirusTotal API rate limit exceeded")
                else:
                    self.logger.error(f"VirusTotal API error: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error checking VirusTotal: {e}")

        return None

    def scan_file(self, file_path: str, verbose: bool = False) -> Dict:
        """Scan a single file with enhanced threat detection."""
        result = {
            'file_path': file_path,
            'status': 'clean',
            'hash': None,
            'error': None,
            'threat_info': None
        }

        try:
            if verbose:
                console.print(f"[blue]Scanning file:[/blue] {file_path}")
            
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                result['status'] = 'error'
                result['error'] = 'Hash calculation failed'
                return result

            result['hash'] = file_hash
            
            # Check for EICAR test file
            if file_hash == self.eicar_hash:
                if verbose:
                    console.print(f"[red]⚠️  EICAR test file detected![/red]")
                result['status'] = 'malicious'
                result['threat_info'] = {
                    'name': 'EICAR-TEST-FILE',
                    'severity': 'High',
                    'details': {}
                }
                self.logger.warning(f"EICAR test file detected: {file_path}")
                return result

            # Check with VirusTotal if API key is available
            if self.vt_api_key:
                if verbose:
                    console.print(f"[blue]Checking with VirusTotal API...[/blue]")
                try:
                    self._respect_vt_rate_limit()
                    params = {
                        'apikey': self.vt_api_key,
                        'resource': file_hash
                    }
                    response = requests.get(VIRUSTOTAL_API_URL, params=params, timeout=30)
                    
                    if response.status_code == 200:
                        vt_result = response.json()
                        if verbose:
                            console.print(f"[blue]VirusTotal response received[/blue]")
                        
                        if vt_result.get('response_code') == 1:
                            positives = vt_result.get('positives', 0)
                            total = vt_result.get('total', 0)
                            
                            if positives > 0:
                                if verbose:
                                    console.print(f"[red]⚠️  Found {positives}/{total} detections on VirusTotal[/red]")
                                
                                # Determine severity based on detection ratio
                                severity = "Low"
                                if positives > 10:
                                    severity = "High"
                                elif positives > 5:
                                    severity = "Medium"
                                
                                result['status'] = 'malicious'
                                result['threat_info'] = {
                                    'name': f"Multiple Detections ({positives} engines)",
                                    'severity': severity,
                                    'details': {
                                        'total_engines': total,
                                        'positive_detections': positives,
                                        'scan_date': vt_result.get('scan_date', ''),
                                        'permalink': vt_result.get('permalink', '')
                                    }
                                }
                                return result
                            elif verbose:
                                console.print("[green]No detections on VirusTotal[/green]")
                    elif response.status_code == 204:
                        if verbose:
                            console.print("[yellow]VirusTotal API rate limit exceeded[/yellow]")
                        self.logger.warning("VirusTotal API rate limit exceeded")
                    else:
                        if verbose:
                            console.print(f"[yellow]VirusTotal API error: {response.status_code}[/yellow]")
                        self.logger.error(f"VirusTotal API error: {response.status_code}")
                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]Error checking VirusTotal: {str(e)}[/yellow]")
                    self.logger.error(f"Error checking VirusTotal: {e}")
            elif verbose:
                console.print("[yellow]VirusTotal API key not configured[/yellow]")
            
            return result
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            if verbose:
                console.print(f"[red]Error scanning {file_path}: {str(e)}[/red]")
            self.logger.error(f"Error scanning {file_path}: {e}")
            return result

    def scan_directory(self, directory: str) -> Generator[Dict, None, None]:
        """Recursively scan directory using parallel processing and batching."""
        batch = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                batch.append(file_path)
                
                if len(batch) >= SCAN_BATCH_SIZE:
                    for result in self._scan_batch(batch):
                        yield result
                    batch = []
        
        if batch:
            for result in self._scan_batch(batch):
                yield result

    def _scan_batch(self, file_paths: List[str]) -> List[Dict]:
        """Scan a batch of files in parallel."""
        futures = []
        results = []
        
        for file_path in file_paths:
            future = self.thread_pool.submit(self.scan_file, file_path)
            futures.append(future)
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error in scan batch: {e}")
        
        return results

    def display_results(self, results: List[Dict]):
        """Display scan results in a formatted table."""
        # Count statistics
        total = len(results)
        clean = sum(1 for r in results if r['status'] == 'clean')
        malicious = sum(1 for r in results if r['status'] == 'malicious')
        errors = sum(1 for r in results if r['status'] == 'error')
        
        # Create and display statistics table
        table = Table(title="📊 Scan Results")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="magenta")
        table.add_column("Percentage", justify="right", style="green")
        
        table.add_row("Total Files", str(total), f"{100.0:.1f}%")
        table.add_row("Clean", str(clean), f"{(clean/total*100):.1f}%" if total > 0 else "0.0%")
        table.add_row("Malicious", str(malicious), f"{(malicious/total*100):.1f}%" if total > 0 else "0.0%")
        table.add_row("Errors", str(errors), f"{(errors/total*100):.1f}%" if total > 0 else "0.0%")
        
        console.print(table)
        
        # Display status message
        if malicious > 0:
            console.print("\n[red]⚠️ Malicious files detected! Please review the detailed results.[/red]")
            # Display malicious file details if any found
            threat_table = Table(title="⚠️  Detected Threats")
            threat_table.add_column("File Path", style="red")
            threat_table.add_column("Hash", style="yellow")
            threat_table.add_column("Risk Level", style="magenta")
            
            for result in results:
                if result['status'] == 'malicious':
                    threat_table.add_row(
                        result['file_path'],
                        result['hash'],
                        result.get('threat_info', {}).get('severity', 'Unknown')
                    )
            console.print(threat_table)
        else:
            console.print("\n[green]✅ All scanned files are clean and safe![/green]")

def main():
    """CLI entry point with performance optimizations."""
    import argparse
    
    parser = argparse.ArgumentParser(description='High-Performance Malicious File Detector')
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--signatures', help='Path to signatures CSV file')
    parser.add_argument('--hash-type', choices=['md5', 'sha256'], default='sha256',
                      help='Hash algorithm to use (default: sha256)')
    
    args = parser.parse_args()
    
    scanner = MaliciousFileScanner(args.signatures, args.hash_type)
    
    if os.path.isfile(args.path):
        result = scanner.scan_file(args.path)
        if result['status'] == 'malicious':
            print(f"⚠️  MALICIOUS FILE DETECTED: {args.path}")
            print(f"Hash: {result['hash']}")
        elif result['status'] == 'clean':
            print(f"✅ File is clean: {args.path}")
        else:
            print(f"❌ Error scanning file: {result['error']}")
    
    elif os.path.isdir(args.path):
        results = list(scanner.scan_directory(args.path))
        scanner.display_results(results)
    
    else:
        print(f"Error: Path {args.path} does not exist")

if __name__ == "__main__":
    main() 