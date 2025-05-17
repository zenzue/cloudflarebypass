#!/usr/bin/env python3
import argparse
import requests, socket, json
from dns import resolver
import threading

SHODAN_API_KEY = "YOUR_SHODAN_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_KEY"

def resolve_dns(domain):
    records = {"A": [], "AAAA": [], "MX": [], "SPF": []}
    try:
        for rtype in records.keys():
            answers = resolver.resolve(domain, rtype, lifetime=3)
            for r in answers:
                records[rtype].append(str(r))
    except:
        pass
    return records

def get_subdomains_from_crtsh(domain):
    print("[*] Searching Certificate Transparency logs...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        r = requests.get(url, timeout=10)
        for cert in r.json():
            name = cert.get("name_value", "")
            for entry in name.split("\n"):
                if domain in entry:
                    subdomains.add(entry.strip())
    except:
        pass
    return list(subdomains)

def resolve_subdomains(subdomains):
    ip_set = set()
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            ip_set.add(ip)
        except:
            continue
    return list(ip_set)

def check_origin(ip, domain):
    try:
        headers = {'Host': domain}
        r = requests.get(f"http://{ip}", headers=headers, timeout=5)
        server = r.headers.get("Server", "")
        if r.status_code == 200 and "cloudflare" not in server.lower():
            print(f"[+] Possible Origin IP: {ip}")
            print(f"    -> Server Header: {server}")
            return True
    except:
        pass
    return False

def securitytrails_passive_dns(domain):
    print("[*] Querying SecurityTrails (if API key available)...")
    ip_list = []
    if not SECURITYTRAILS_API_KEY:
        return ip_list
    headers = {'APIKEY': SECURITYTRAILS_API_KEY}
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/dns/history/a"
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        for record in data.get("records", []):
            ip = record.get("ip", "")
            if ip:
                ip_list.append(ip)
    except:
        pass
    return ip_list

def search_shodan(domain):
    print("[*] Shodan Lookup...")
    result_ips = []
    if not SHODAN_API_KEY:
        return result_ips
    try:
        query = f'hostname:"{domain}"'
        url = f'https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}'
        r = requests.get(url)
        for item in r.json().get('matches', []):
            ip = item.get("ip_str")
            if ip:
                result_ips.append(ip)
    except:
        pass
    return result_ips

def scan_ports(ip, ports=[80, 443, 8080, 8443]):
    open_ports = []
    for port in ports:
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect((ip, port))
            open_ports.append(port)
        except:
            continue
        s.close()
    return open_ports

def vhost_scan(ip, wordlist, threads=10):
    print(f"[*] Starting vHost brute-force on {ip}...")
    with open(wordlist, 'r') as f:
        lines = f.readlines()

    def worker(hosts):
        for sub in hosts:
            sub = sub.strip()
            if not sub:
                continue
            headers = {"Host": sub}
            try:
                r = requests.get(f"http://{ip}", headers=headers, timeout=3)
                if r.status_code == 200:
                    print(f"[+] Found vHost {sub} on {ip}")
            except:
                continue

    chunk_size = len(lines) // threads
    threads_list = []
    for i in range(threads):
        chunk = lines[i * chunk_size:(i + 1) * chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        threads_list.append(t)
        t.start()

    for t in threads_list:
        t.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Cloudflare Origin IP Bypass Tool by w01f")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--vhost", help="Path to vHost wordlist", default=None)
    args = parser.parse_args()

    target = args.domain.strip()

    print("[*] Passive DNS Records:")
    records = resolve_dns(target)
    print(json.dumps(records, indent=2))

    subdomains = get_subdomains_from_crtsh(target)
    print(f"[+] Discovered {len(subdomains)} subdomains from cert logs")

    print("[*] Resolving subdomain IPs...")
    resolved_ips = resolve_subdomains(subdomains)
    print(f"[+] Resolved IPs: {resolved_ips}")

    print("[*] Checking resolved IPs for origin exposure:")
    for ip in resolved_ips:
        check_origin(ip, target)

    if SECURITYTRAILS_API_KEY:
        old_ips = securitytrails_passive_dns(target)
        print(f"[+] SecurityTrails Historical IPs: {old_ips}")
        for ip in old_ips:
            check_origin(ip, target)

    if SHODAN_API_KEY:
        shodan_ips = search_shodan(target)
        print(f"[+] Shodan Found IPs: {shodan_ips}")
        for ip in shodan_ips:
            check_origin(ip, target)

    print("[*] Scanning open ports:")
    for ip in resolved_ips:
        ports = scan_ports(ip)
        if ports:
            print(f"[+] Open ports on {ip}: {ports}")

    if args.vhost:
        for ip in resolved_ips:
            vhost_scan(ip, args.vhost)
