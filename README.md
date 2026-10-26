# Recon8

An automated reconnaissance tool for penetration testers and security researchers.

## What it does

Give it a domain or IP and it automatically runs:

- **Nmap** — open ports, services, and version detection
- **Whois** — domain ownership and registration details
- **DNS enumeration** — A, MX, NS, TXT, and CNAME records
- **Subdomain brute-forcing** — discovers hidden subdomains (domain targets only)
- **Reverse DNS** — resolves hostname from IP (IP targets only)
- **Port insights** — flags high-risk open ports (SMB, RDP, FTP, HTTPS)

## Requirements

- Python 3
- Nmap installed on the system
- Kali Linux or any Debian-based Linux

## Installation

```bash
git clone https://github.com/AeroTo/recon8.git
cd recon8
./install.sh
```

## Usage

```bash
python3 recon8.py <target>
```

Examples:

```bash
python3 recon8.py example.com
python3 recon8.py 192.168.1.1
```

## Disclaimer

This tool is for authorized testing and educational purposes only.
