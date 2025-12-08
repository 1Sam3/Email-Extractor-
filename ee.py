import re
import sys
import hashlib
import ipaddress
import requests
import email
from email import policy
from email.parser import BytesParser
import argparse
import json
import chardet
import tldextract
from tabulate import tabulate
from colorama import Fore, Style, init
import asyncio
import aiohttp

init(autoreset=True)


def defang_ip(ip): return ip.replace('.', '[.]')

def defang_url(url):
    url = re.sub(r'^https?://', lambda m: 'hxxps[://]' if m.group(0).startswith('https') else 'hxxp[://]', url)
    return url.replace('.', '[.]')


def file_hashes(data):
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }


def is_reserved_ip(ip):
    ranges = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','0.0.0.0/8','100.64.0.0/10','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4']
    for r in ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r): return True
    return False

async def ip_lookup_async(ip, session, cache={}):
    if is_reserved_ip(ip): return None
    if ip in cache: return cache[ip]
    try:
        async with session.get(f'https://ipinfo.io/{ip}/json', timeout=5) as resp:
            if resp.status == 200:
                cache[ip] = await resp.json()
                return cache[ip]
    except: pass
    return None


def read_file(path):
    with open(path, 'rb') as f: content = f.read()
    return BytesParser(policy=policy.default).parsebytes(content)


def extract_iocs(msg):
    ips, urls, attachments = set(), set(), []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart': continue
        payload = part.get_payload(decode=True)
        if payload:
            enc = chardet.detect(payload)['encoding']
            try: text = payload.decode(enc, errors='ignore')
            except: text = ''
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
            urls.update(re.findall(r'https?://[^\s<>"]+', text))
        if part.get('Content-Disposition') and part.get_filename():
            data = part.get_payload(decode=True)
            if data:
                attachments.append({
                    'filename': part.get_filename(),
                    'type': part.get_content_type(),
                    'size_bytes': len(data),
                    **file_hashes(data)
                })
    for header in msg.values():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header))
    valid = []
    for ip in ips:
        try: ipaddress.ip_address(ip); valid.append(ip)
        except: pass
    return list(set(valid)), list(set(urls)), attachments


def extract_headers(msg):
    keys = ["Date","Subject","To","From","Reply-To","Return-Path","Message-ID","X-Originating-IP","X-Sender-IP","Authentication-Results"]
    headers = {k: v for k,v in msg.items() if k in keys}
    headers['Received'] = [v for k,v in msg.items() if k.lower() == 'received']
    return headers


async def vt_check_url(session, url, vt_key):
    if not vt_key: return None
    headers = {'x-apikey': vt_key}
    try:
        async with session.get(f'https://www.virustotal.com/api/v3/urls/{requests.utils.quote(url)}', headers=headers, timeout=5) as resp:
            if resp.status == 200: return await resp.json()
    except: pass
    return None

async def abuse_check_ip(session, ip, abuse_key):
    if not abuse_key: return None
    headers = {'Key': abuse_key, 'Accept': 'application/json'}
    try:
        async with session.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}', headers=headers, timeout=5) as resp:
            if resp.status == 200: return await resp.json()
    except: pass
    return None


def parse_auth_results(auth_header):
    color_map = {'pass': Fore.GREEN, 'fail': Fore.RED, 'none': Fore.YELLOW}
    parts = auth_header.split() if auth_header else []
    results = {}
    for p in parts:
        for key in ['spf','dkim','dmarc']:
            if p.startswith(key+'='):
                results[key.upper()] = (color_map.get(p.split('=')[1], Fore.WHITE), p.split('=')[1])
    return results


async def print_color_tables(output, vt_key=None, abuse_key=None):
    print(Fore.CYAN + "\n=== Headers ===")
    for k,v in output['Headers'].items():
        if isinstance(v,list):
            for line in v: print(Fore.YELLOW + f"{k}: " + Fore.WHITE + line)
        else:
            print(Fore.YELLOW + f"{k}: " + Fore.WHITE + v)

    auth = parse_auth_results(output['Headers'].get('Authentication-Results'))
    for key,(color,val) in auth.items():
        print(color + f"{key}: {val}")

    print(Fore.GREEN + "\n=== IP Addresses ===")
    async with aiohttp.ClientSession() as session:
        tasks = [abuse_check_ip(session, item['ip'], abuse_key) for item in output['IPs']]
        abuses = await asyncio.gather(*tasks)

        rows = []
        for item, abuse in zip(output['IPs'], abuses):
            info = item['info'] or {}
            rows.append([
                Fore.WHITE + item['raw'], Fore.CYAN + item['ip'], info.get('city',''), info.get('country',''), info.get('org',''),
                'Abuse!' if abuse and abuse.get('data',{}).get('abuseConfidenceScore',0) > 0 else ''
            ])
        print(tabulate(rows, headers=["Raw","Defanged","City","Country","Org","Abuse"], tablefmt="fancy_grid"))

    print(Fore.GREEN + "\n=== URLs ===")
    async with aiohttp.ClientSession() as session:
        tasks = [vt_check_url(session, u['url'], vt_key) for u in output['URLs']]
        vts = await asyncio.gather(*tasks)
        urows = []
        for u, vt in zip(output['URLs'], vts):
            domain = f"{u['subdomain']}.{u['domain']}.{u['suffix']}"
            vt_status = 'Malicious' if vt and vt.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0) > 0 else ''
            urows.append([u['url'], u['expanded'], domain, vt_status])
        print(tabulate(urows, headers=["URL","Expanded","Domain","VT Status"], tablefmt="fancy_grid"))

    print(Fore.GREEN + "\n=== Attachments ===")
    for a in output['Attachments']:
        print(Fore.YELLOW + f"File: {a['filename']}  Size: {a['size_bytes']} bytes")

    print(Fore.CYAN + "\n=== Statistics ===")
    for k,v in output['Stats'].items(): print(Fore.YELLOW + f"{k}: " + Fore.WHITE + str(v))


def process_file(path, save_json=True, vt_key=None, abuse_key=None):
    msg = read_file(path)
    ips, urls, attachments = extract_iocs(msg)
    headers = extract_headers(msg)

    ip_info = {ip: None for ip in ips}
    defanged_ips = [defang_ip(ip) for ip in ips]
    defanged_urls = [defang_url(u) for u in urls]
    url_ext = [{'url': u,'expanded': u,'subdomain': tldextract.extract(u).subdomain,'domain': tldextract.extract(u).domain,'suffix': tldextract.extract(u).suffix} for u in urls]

    output = {
        'file_name': path,
        'Headers': headers,
        'IPs': [{'ip': d,'raw': i,'info': ip_info[i],'abuse': None} for i,d in zip(ips,defanged_ips)],
        'URLs': url_ext,'Attachments': attachments,'Stats': {'email_size_bytes':len(msg.as_bytes()),'total_attachments':len(attachments),'unique_urls':len(urls),'unique_ips':len(ips)},'DKIM': None
    }

    asyncio.run(print_color_tables(output, vt_key=vt_key, abuse_key=abuse_key))

    if save_json:
        import os
        os.makedirs('output_reports', exist_ok=True)
        out = f"output_reports/output_{os.path.basename(path)}.json"
        with open(out,'w') as f: json.dump(output,f,indent=4)
        print(Fore.GREEN + f"\nSaved JSON: {out}")

    return output


def interactive(vt_key=None, abuse_key=None):
    print(Fore.CYAN + "\n=== Interactive Mode ===")
    while True:
        path = input(Fore.YELLOW + "Enter EML file path (or 'exit'): ").strip()
        if path.lower() == 'exit': break
        process_file(path, vt_key=vt_key, abuse_key=abuse_key)


def main():
    parser = argparse.ArgumentParser(description='Enhanced Email Extractor')
    parser.add_argument('files', nargs='*', help='EML files')
    parser.add_argument('--json', action='store_true', help='Save JSON')
    parser.add_argument('--interactive', action='store_true', help='Run interactive mode')
    parser.add_argument('--vt-key', type=str, help='VirusTotal API key')
    parser.add_argument('--abuse-key', type=str, help='AbuseIPDB API key')
    args = parser.parse_args()

    if args.interactive: return interactive(vt_key=args.vt_key, abuse_key=args.abuse_key)

    for f in args.files:
        print(Fore.CYAN + f"\n=== Processing: {f} ===")
        process_file(f, save_json=args.json, vt_key=args.vt_key, abuse_key=args.abuse_key)

if __name__ == '__main__':
    main()
