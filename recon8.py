#!/usr/bin/env python3

import argparse
import nmap
import whois
import dns.resolver
import json
import sys
import socket
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def detect_target_type(target):
    try:
        socket.inet_aton(target)
        return 'ip'
    except socket.error:
        return 'domain'

def reverse_dns(ip):
    print(f"{Fore.CYAN}[*] Running Reverse DNS on {ip}...{Style.RESET_ALL}")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {'hostname': hostname}
    except Exception as e:
        return {'error': str(e)}

def run_nmap(target):
    print(f"{Fore.CYAN}[*] Running Nmap scan on {target}...{Style.RESET_ALL}")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV -O --open')
    
    results = {}
    for host in scanner.all_hosts():
        results['host'] = host
        results['state'] = scanner[host].state()
        results['ports'] = []
        
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                port_info = scanner[host][proto][port]
                results['ports'].append({
                    'port': port,
                    'state': port_info['state'],
                    'service': port_info['name'],
                    'version': port_info['version']
                })
    
    return results

def run_whois(target):
    print(f"{Fore.CYAN}[*] Running Whois lookup on {target}...{Style.RESET_ALL}")
    try:
        w = whois.whois(target)
        results = {
            'domain': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
            'name_servers': w.name_servers
        }
        return results
    except Exception as e:
        return {'error': str(e)}

def run_dns(target):
    print(f"{Fore.CYAN}[*] Running DNS enumeration on {target}...{Style.RESET_ALL}")
    results = {}
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(target, record)
            results[record] = [str(r) for r in answers]
        except Exception:
            results[record] = []
    
    return results

def run_subdomain_brute(target, wordlist=None):
    print(f"{Fore.CYAN}[*] Running subdomain brute-force on {target}...{Style.RESET_ALL}")
    found = []
    
    subdomains = wordlist if wordlist else [
        'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging',
        'test', 'portal', 'vpn', 'remote', 'blog', 'shop', 'app',
        'secure', 'login', 'dashboard', 'cdn', 'static', 'docs'
    ]
    
    for sub in subdomains:
        full = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(full)
            found.append({'subdomain': full, 'ip': ip})
            print(f"  {Fore.GREEN}[+] Found: {full} -> {ip}{Style.RESET_ALL}")
        except:
            pass
    
    return found

def run_port_checks(target, ports):
    results = {}
    open_ports = [p['port'] for p in ports]
    
    if 445 in open_ports:
        print(f"{Fore.CYAN}[*] SMB detected on port 445 — checking...{Style.RESET_ALL}")
        results['smb'] = 'Port 445 open — potential SMB exposure. Check for misconfigurations.'
    
    if 443 in open_ports:
        print(f"{Fore.CYAN}[*] HTTPS detected on port 443 — noting SSL...{Style.RESET_ALL}")
        results['ssl'] = 'Port 443 open — consider running sslscan for certificate details.'
    
    if 3389 in open_ports:
        print(f"{Fore.CYAN}[*] RDP detected on port 3389...{Style.RESET_ALL}")
        results['rdp'] = 'Port 3389 open — RDP exposed. High risk if internet-facing.'
    
    if 21 in open_ports:
        print(f"{Fore.CYAN}[*] FTP detected on port 21...{Style.RESET_ALL}")
        results['ftp'] = 'Port 21 open — check for anonymous FTP login.'
    
    return results

def generate_report(target, target_type, nmap_results, whois_results, dns_results, subdomain_results, port_checks, reverse_dns_result, elapsed):
    print(f"\n{Fore.YELLOW}{'=' * 50}")
    print(f"  RECON8 REPORT — {target}")
    print(f"{'=' * 50}{Style.RESET_ALL}")

    if target_type == 'ip' and reverse_dns_result:
        print(f"\n{Fore.YELLOW}[ REVERSE DNS ]{Style.RESET_ALL}")
        if 'hostname' in reverse_dns_result:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Hostname: {reverse_dns_result['hostname']}")
        else:
            print(f"  {Fore.RED}[!] {reverse_dns_result['error']}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}[ NMAP ]{Style.RESET_ALL}")
    if 'ports' in nmap_results:
        for p in nmap_results['ports']:
            version = p['version'] if p['version'] else 'unknown'
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Port {p['port']}/tcp  {Fore.GREEN}{p['state']}{Style.RESET_ALL}  {p['service']}  {version}")
    else:
        print(f"  {Fore.RED}[-] No open ports found.{Style.RESET_ALL}")

    if port_checks:
        print(f"\n{Fore.YELLOW}[ PORT INSIGHTS ]{Style.RESET_ALL}")
        for key, msg in port_checks.items():
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    print(f"\n{Fore.YELLOW}[ WHOIS ]{Style.RESET_ALL}")
    if 'error' in whois_results:
        print(f"  {Fore.RED}[!] Error: {whois_results['error']}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Domain:      {whois_results['domain']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Registrar:   {whois_results['registrar']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Created:     {whois_results['creation_date']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Expires:     {whois_results['expiration_date']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Nameservers: {whois_results['name_servers']}")

    print(f"\n{Fore.YELLOW}[ DNS ]{Style.RESET_ALL}")
    found_any = False
    for record, values in dns_results.items():
        if values:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {record}: {', '.join(values)}")
            found_any = True
    if not found_any:
        print(f"  {Fore.RED}[-] No DNS records found.{Style.RESET_ALL}")

    if target_type == 'domain':
        print(f"\n{Fore.YELLOW}[ SUBDOMAINS ]{Style.RESET_ALL}")
        if subdomain_results:
            for s in subdomain_results:
                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {s['subdomain']} -> {s['ip']}")
        else:
            print(f"  {Fore.RED}[-] No subdomains found.{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    print(f"  Scan completed in {Fore.GREEN}{elapsed:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Recon8 - Automated Reconnaissance Tool')
    parser.add_argument('target', help='Target domain or IP address')
    args = parser.parse_args()
    
    target = args.target
    start_time = time.time()
    
    print(f"\n{Fore.YELLOW}[+] Starting Recon8 on target: {target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    target_type = detect_target_type(target)
    print(f"{Fore.CYAN}[*] Target type: {target_type}{Style.RESET_ALL}")
    
    reverse_dns_result = None
    if target_type == 'ip':
        reverse_dns_result = reverse_dns(target)
    
    nmap_results = run_nmap(target)
    whois_results = run_whois(target)
    dns_results = run_dns(target)
    
    subdomain_results = []
    if target_type == 'domain':
        subdomain_results = run_subdomain_brute(target)
    
    port_checks = {}
    if 'ports' in nmap_results:
        port_checks = run_port_checks(target, nmap_results['ports'])
    
    elapsed = time.time() - start_time
    
    generate_report(target, target_type, nmap_results, whois_results, dns_results, subdomain_results, port_checks, reverse_dns_result, elapsed)
    print(f"\n{Fore.GREEN}[+] Recon8 complete.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
