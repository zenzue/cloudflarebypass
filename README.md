# Cloudflare Origin IP Bypass Tool

An advanced reconnaissance tool written in Python to discover the real IP address of web servers behind Cloudflare. Useful for penetration testing, bug bounty, red teaming, and CTF scenarios.

**Author**: w01f

---

## Features

- Certificate Transparency log scraping (`crt.sh`)
- Passive DNS record resolution (A, AAAA, MX, SPF)
- Subdomain resolution and IP collection
- Origin IP detection via HTTP probing
- Optional:
  - SecurityTrails historical IP lookup
  - Shodan API integration
  - Virtual Host (vHost) brute-force scanning
- Port scanning of discovered IPs

---

## Installation

```bash
pip install requests dnspython
````

---

## Usage

```bash
python3 cloudflare_bypass.py <target_domain>
```

Optional vHost brute-force:

```bash
python3 cloudflare_bypass.py <target_domain> --vhost vhosts.txt
```

---

## Arguments

| Argument   | Description                      |
| ---------- | -------------------------------- |
| `<domain>` | Target domain (e.g. example.com) |
| `--vhost`  | Path to vHost wordlist file      |

API Keys can be configured at the top of the script:

```python
SHODAN_API_KEY = "your_shodan_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"
```

---

## Example Output

```text
[*] Passive DNS Records:
{
  "A": ["104.21.1.1"],
  "AAAA": [],
  "MX": ["mx.example.com."],
  "SPF": []
}
[+] Discovered 25 subdomains from cert logs
[+] Resolved IPs: ['192.0.2.10', '198.51.100.15']
[+] Possible Origin IP: 192.0.2.10
    -> Server Header: nginx
[+] Open ports on 192.0.2.10: [80, 443]
```

---

## Disclaimer

This tool is intended for **authorized security testing and educational use only**. Do not use it against systems you do not have explicit permission to test.

---
