#!/usr/bin/env python3

import socket
import json
import time
import random
import datetime
import ipaddress
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def generate_random_subnets(num_subnets=10, prefix=24):
    """
    Generates random IPv4 subnets (default /24).
    Skips private/reserved ranges, returns list like ['8.8.8.0/24', ...].
    """
    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("100.64.0.0/10")
    ]
    def is_private_or_reserved(net):
        return any(net.subnet_of(r) for r in private_ranges)

    subnets = []
    while len(subnets) < num_subnets:
        octets = [random.randint(1, 254) for _ in range(4)]
        cidr_str = f"{'.'.join(map(str, octets))}/{prefix}"
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if not is_private_or_reserved(net):
                subnets.append(str(net))
        except:
            pass
    return subnets

class ExtremeScanner:
    """
    Ultra-aggressive, near-full-port-range scanner:
      - Very short timeouts
      - Huge concurrency
      - Recursively discovers new subnets from data
      - Runs in a loop
    """
    def __init__(self,
                 sock_timeout=0.01,
                 max_workers=None,
                 batch_size=8192,
                 retries=0,
                 start_port=1,
                 end_port=65535):
        self.scan_id = int(time.time())
        self.sock_timeout = sock_timeout
        self.max_workers = max_workers or min(16384, (os.cpu_count() or 1)*1024)
        self.batch_size = batch_size
        self.retries = retries
        self.start_port = start_port
        self.end_port = end_port
        # This queue will hold newly discovered subnets (strings) for recursive scanning
        self.new_subnets = set()

    def scan_port(self, ip_str, port):
        """
        Attempt a TCP connect to ip_str:port with no banner grabbing 
        (faster). For demonstration, we do minimal recursion:
        if port 80 or 443 is open, we do a short "banner" check for 
        host references (just a toy example).
        """
        for _ in range(self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.sock_timeout)
                    if sock.connect_ex((ip_str, port)) == 0:
                        # Found open port
                        print(f"OPEN: {ip_str}:{port}")
                        # Quick attempt to read a snippet if HTTP/HTTPS port
                        if port in (80, 443):
                            try:
                                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                                sock.settimeout(0.1)
                                resp = sock.recv(2048).decode(errors='ignore')
                                # Simple parse of something that looks like IP or subnet
                                self._parse_banner_for_subnets(resp)
                            except:
                                pass
                        return {
                            "ip": ip_str,
                            "port": port,
                            "timestamp": datetime.datetime.utcnow().isoformat()
                        }
            except:
                pass
        return None

    def _parse_banner_for_subnets(self, banner_text):
        """
        Just a toy parser that looks for something that might 
        look like an IP in text, then forms a /24 out of it, 
        and adds it to self.new_subnets if public.
        """
        tokens = banner_text.split()
        for t in tokens:
            # Quick check if looks like X.X.X.X
            parts = t.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                ip_candidate = ".".join(parts)
                try:
                    net_candidate = ipaddress.ip_network(ip_candidate + "/24", strict=False)
                    if (net_candidate.num_addresses > 1 and
                        not (net_candidate.is_private or net_candidate.is_reserved)):
                        print(f"[*] Found new subnet candidate: {net_candidate}")
                        self.new_subnets.add(str(net_candidate))
                except:
                    pass

    def scan_batch(self, batch):
        results = []
        for ip_str, port in batch:
            res = self.scan_port(ip_str, port)
            if res:
                results.append(res)
        return results

    def scan_subnet(self, subnet):
        """
        Build (ip, port) tasks for the entire range, in batches.
        """
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())  # all valid host IPs
        print(f"\n=== SCANNING SUBNET: {subnet}, {len(hosts)} hosts, ports {self.start_port}-{self.end_port} ===")
        start_t = time.time()

        tasks = [(str(ip), p)
                 for ip in hosts
                 for p in range(self.start_port, self.end_port+1)]

        batches = [tasks[i:i+self.batch_size]
                   for i in range(0, len(tasks), self.batch_size)]

        open_results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            futures = [exe.submit(self.scan_batch, b) for b in batches]
            for fut in as_completed(futures):
                partial_result = fut.result()
                if partial_result:
                    open_results.extend(partial_result)

        elapsed = time.time() - start_t
        print(f"Completed scanning subnet {subnet} in {elapsed:.2f}s. "
              f"Open ports found: {len(open_results)}")
        return open_results

    def scan_subnets(self, subnets):
        """
        Scan each subnet in subnets list. 
        Return full consolidated list of open ports.
        """
        grand = []
        for s in subnets:
            results = self.scan_subnet(s)
            grand.extend(results)
        return grand

    def run_recursive_scans(self, initial_subnets, sleep_time=60):
        """
        Continuously:
          - Scan the provided subnets
          - Scan any newly discovered subnets
          - Sleep, repeat
        """
        scanned_set = set(initial_subnets)  # track what's scanned
        while True:
            # Combine new subnets discovered with ones we haven't scanned yet
            to_scan = list(scanned_set)
            new_set = list(self.new_subnets - scanned_set)
            if new_set:
                print(f"\n[!] Found {len(new_set)} new subnets to scan recursively.")
                to_scan.extend(new_set)
                scanned_set.update(new_set)

            # Scan them all
            if not to_scan:
                print("No subnets to scan. Sleeping...")
                time.sleep(sleep_time)
                continue

            print(f"\nStarting a full round of scans on {len(to_scan)} subnets.")
            self.scan_id = int(time.time())  # new scan ID each round
            all_open = self.scan_subnets(to_scan)

            # Save JSON
            stamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            fname = f"massive_scan_{self.scan_id}_{stamp}.json"
            out_data = {
                "scan_id": self.scan_id,
                "time": stamp,
                "subnets_scanned": to_scan,
                "results_count": len(all_open),
                "results": all_open,
                "discovered_subnets": list(self.new_subnets)
            }
            with open(fname, "w") as fp:
                json.dump(out_data, fp, indent=2)

            print(f"[SCAN ROUND COMPLETE]: {len(all_open)} open ports total. Results saved to {fname}\n")
            print(f"Sleeping {sleep_time}s before next round...\n")
            time.sleep(sleep_time)

def main():
    # 1) Generate random subnets + known subnets
    random_subs = generate_random_subnets(num_subnets=5, prefix=24)
    known_subs = [
        "8.8.8.0/24",
        "8.8.4.0/24"
    ]
    initial_subnets = set(known_subs + random_subs)

    # 2) Create an "ExtremeScanner" with:
    #    - ultra-short timeouts
    #    - huge concurrency
    #    - nearly all ports
    #    - no retries
    scanner = ExtremeScanner(
        sock_timeout=0.01,
        max_workers=None,    # Let code pick max
        batch_size=8192,
        retries=0,
        start_port=1,
        end_port=65535
    )

    # 3) Start an infinite loop scanning those subnets
    #    + any newly discovered subnets from banners
    try:
        scanner.run_recursive_scans(initial_subnets, sleep_time=60)
    except KeyboardInterrupt:
        print("\nExiting. No more scanning.")
        sys.exit(0)

if __name__ == "__main__":
    main()
