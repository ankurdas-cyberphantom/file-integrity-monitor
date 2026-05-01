#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Monitors files and directories for unauthorized changes using cryptographic hashing.
"""

import hashlib
import os
import sys
import time
import json
import argparse
import signal
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
LOG_FILE = "fim.log"
DB_FILE = "fim_db.json"
REPORT_FILE = "fim_report.json"
DEFAULT_ALGORITHM = "sha256"
SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
BANNER = f"""{Fore.CYAN}
╔══════════════════════════════════════════════╗
║        File Integrity Monitor  v2.0          ║
║        github.com/ankurdas-cyberphantom/fim          ║
╚══════════════════════════════════════════════╝
{Style.RESET_ALL}"""


# ──────────────────────────────────────────────
# Core Functions
# ──────────────────────────────────────────────

def compute_hash(file_path: str, algorithm: str = DEFAULT_ALGORITHM) -> Optional[str]:
    """Compute cryptographic hash of a file in chunks (memory-safe)."""
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        logger.warning(f"Cannot hash '{file_path}': {e}")
        return None


def get_file_metadata(file_path: str) -> dict:
    """Return file size, permissions, and modification time."""
    try:
        stat = os.stat(file_path)
        return {
            "size_bytes": stat.st_size,
            "permissions": oct(stat.st_mode),
            "last_modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
    except OSError:
        return {}


def collect_targets(paths: list[str]) -> list[str]:
    """Expand dirs to individual file paths recursively."""
    targets = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            targets.append(str(path.resolve()))
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file():
                    targets.append(str(f.resolve()))
        else:
            logger.warning(f"Path not found: {p}")
    return sorted(set(targets))


# ──────────────────────────────────────────────
# Database (JSON-based)
# ──────────────────────────────────────────────

def load_db(db_path: str = DB_FILE) -> dict:
    try:
        with open(db_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_db(db: dict, db_path: str = DB_FILE):
    with open(db_path, "w") as f:
        json.dump(db, f, indent=4)


# ──────────────────────────────────────────────
# Modes
# ──────────────────────────────────────────────

def baseline(paths: list[str], algorithm: str = DEFAULT_ALGORITHM, db_path: str = DB_FILE):
    """Create or update the baseline hash database."""
    print(BANNER)
    targets = collect_targets(paths)
    if not targets:
        logger.error("No valid files found to baseline.")
        return

    db = {}
    print(f"{Fore.YELLOW}[*] Baselining {len(targets)} file(s) using {algorithm.upper()}...{Style.RESET_ALL}\n")
    for fp in targets:
        h = compute_hash(fp, algorithm)
        if h:
            db[fp] = {
                "hash": h,
                "algorithm": algorithm,
                "baselined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                **get_file_metadata(fp),
            }
            print(f"  {Fore.GREEN}✔{Style.RESET_ALL} {fp}")

    save_db(db, db_path)
    logger.info(f"Baseline complete. {len(db)} file(s) stored in '{db_path}'.")
    print(f"\n{Fore.GREEN}[+] Baseline saved → {db_path}{Style.RESET_ALL}")


def check(paths: list[str], algorithm: str = DEFAULT_ALGORITHM,
          db_path: str = DB_FILE, report: bool = False):
    """Compare current hashes against the baseline."""
    print(BANNER)
    db = load_db(db_path)
    if not db:
        logger.error(f"No baseline found at '{db_path}'. Run --baseline first.")
        return

    targets = collect_targets(paths) if paths else list(db.keys())
    results = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "modified": [], "new": [], "deleted": [], "ok": []}

    print(f"{Fore.YELLOW}[*] Checking {len(targets)} file(s)...{Style.RESET_ALL}\n")

    for fp in targets:
        if fp not in db:
            print(f"  {Fore.BLUE}[NEW]{Style.RESET_ALL} {fp}")
            results["new"].append(fp)
            continue

        current_hash = compute_hash(fp, db[fp].get("algorithm", algorithm))
        if current_hash is None:
            print(f"  {Fore.RED}[DELETED/ERROR]{Style.RESET_ALL} {fp}")
            results["deleted"].append(fp)
        elif current_hash != db[fp]["hash"]:
            print(f"  {Fore.RED}[MODIFIED]{Style.RESET_ALL} {fp}")
            print(f"    Old: {db[fp]['hash']}")
            print(f"    New: {current_hash}")
            logger.warning(f"INTEGRITY VIOLATION: {fp}")
            results["modified"].append({"file": fp, "old": db[fp]["hash"], "new": current_hash,
                                        **get_file_metadata(fp)})
        else:
            print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {fp}")
            results["ok"].append(fp)

    # Check for deleted baselines
    for fp in db:
        if fp not in targets and not os.path.exists(fp):
            print(f"  {Fore.RED}[DELETED]{Style.RESET_ALL} {fp}")
            results["deleted"].append(fp)

    # Summary
    print(f"""
{Fore.CYAN}─── Summary ───────────────────────────────────{Style.RESET_ALL}
  ✔ OK:       {len(results['ok'])}
  ⚠ Modified: {len(results['modified'])}
  ✚ New:      {len(results['new'])}
  ✖ Deleted:  {len(results['deleted'])}
""")

    if report:
        with open(REPORT_FILE, "w") as f:
            json.dump(results, f, indent=4)
        print(f"{Fore.GREEN}[+] Report saved → {REPORT_FILE}{Style.RESET_ALL}")

    return results


def watch(paths: list[str], interval: int = 30, algorithm: str = DEFAULT_ALGORITHM,
          db_path: str = DB_FILE):
    """Continuously monitor files and alert on changes."""
    print(BANNER)
    print(f"{Fore.CYAN}[*] Watch mode active — checking every {interval}s. Ctrl+C to stop.{Style.RESET_ALL}\n")

    def _stop(sig, frame):
        print(f"\n{Fore.YELLOW}[!] Stopping watcher.{Style.RESET_ALL}")
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)

    while True:
        results = check(paths, algorithm, db_path, report=False)
        if results and (results["modified"] or results["deleted"]):
            logger.critical(f"ALERT: {len(results['modified'])} modified, "
                            f"{len(results['deleted'])} deleted files detected!")
        time.sleep(interval)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_monitor.py --baseline /etc /var/www
  python file_monitor.py --check /etc /var/www --report
  python file_monitor.py --watch /etc --interval 60
  python file_monitor.py --baseline . --algorithm sha512
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--baseline", action="store_true", help="Create/update baseline hash DB")
    group.add_argument("--check", action="store_true", help="Check files against baseline")
    group.add_argument("--watch", action="store_true", help="Continuously monitor files")

    parser.add_argument("paths", nargs="*", help="Files or directories to monitor")
    parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS,
                        default=DEFAULT_ALGORITHM, help=f"Hash algorithm (default: {DEFAULT_ALGORITHM})")
    parser.add_argument("--db", default=DB_FILE, help=f"Path to baseline DB (default: {DB_FILE})")
    parser.add_argument("--interval", type=int, default=30,
                        help="Watch interval in seconds (default: 30)")
    parser.add_argument("--report", action="store_true",
                        help="Save check results to JSON report")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.paths and not args.check:
        parser.error("Provide at least one file or directory path.")

    if args.baseline:
        baseline(args.paths, args.algorithm, args.db)
    elif args.check:
        check(args.paths or [], args.algorithm, args.db, args.report)
    elif args.watch:
        watch(args.paths, args.interval, args.algorithm, args.db)


if __name__ == "__main__":
    main()
