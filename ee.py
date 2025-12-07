#!/usr/bin/env python3
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

# Defang helpers
def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    url = re.sub(r'^https?://', lambda m: 'hxxps[://]' if m.group(0).startswith('https') else 'hxxp[://]', url)
    url = url.replace('.', '[.]')
    return url

# Hash file
def file_hashes(data):
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }

def is_reserved_ip(ip):
    private_ranges = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']
    reserved_ranges = ['0.0.0.0/8','100.64.0.0/10','169.254.0.0/16','192.0.0.0/24','192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4']
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ip_lookup(ip, cache={}):
    if is_reserved_ip(ip):
        return None
    if ip in cache:
        return cache[ip]
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            cache[ip] = {
                'IP': data.get('ip', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'Location': data.get('loc', ''),
                'ISP': data.get('org', ''),
                'Postal Code': data.get('postal', ''),
                'Timezone': data.get('timezone', ''),
                'ASN': data.get('org', '')
            }
            return cache[ip]
    except Exception:
        pass
    return None

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = BytesParser(policy=policy.default)
    msg = parser.parsebytes(content)
    return msg

def extract_iocs(email_message):
    ips, urls, attachments = set(), set(), []

    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload:
            detected = chardet.detect(payload)
            try:
                payload = payload.decode(detected['encoding'], errors='ignore')
            except Exception:
                payload = ''
            if content_type in ['text/plain', 'text/html']:
                ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
                urls.update(re.findall(r'https?://[^\s<>"\']+', payload))

        if part.get('Content-Disposition') and part.get_filename():
            data = part.get_payload(decode=True)
            if data:
                attachments.append({
                    'filename': part.get_filename(),
                    'type': part.get_content_type(),
                    'size_bytes': len(data),
                    **file_hashes(data)
                })

    # Extract IPs from headers
    for header_value in email_message.values():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))

    # Validate IPs
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass

    return list(set(valid_ips)), list(set(urls)), attachments

def extract_headers(email_message):
    headers_to_extract = ["Date", "Subject", "To", "From", "Reply-To", "Return-Path", "Message-ID", "X-Originating-IP", "X-Sender-IP", "Authentication-Results"]
    headers = {k: v for k, v in email_message.items() if k in headers_to_extract}

    # Include all Received headers for routing analysis
    received_headers = [v for k, v in email_message.items() if k.lower() == 'received']
    headers['Received'] = received_headers
    return headers


def main():
    parser = argparse.ArgumentParser(description='Extract IOCs from EML file')
    parser.add_argument('file', help='Path to EML file')
    parser.add_argument('--json', help='Save output to JSON file', action='store_true')
    args = parser.parse_args()

    email_message = read_file(args.file)
    ips, urls, attachments = extract_iocs(email_message)
    headers = extract_headers(email_message)

    ip_infos = {}
    for ip in ips:
        info = ip_lookup(ip)
        ip_infos[ip] = info

    # Defang outputs
    defanged_ips = [defang_ip(ip) for ip in ips]
    defanged_urls = [defang_url(url) for url in urls]

    # Extract domains from URLs
    url_domains = [{
        'url': u,
        'domain': tldextract.extract(u).domain,
        'subdomain': tldextract.extract(u).subdomain,
        'suffix': tldextract.extract(u).suffix
    } for u in urls]

    output = {
        'IPs': [{'ip': d, 'info': ip_infos[i]} for i, d in zip(ips, defanged_ips)],
        'URLs': url_domains,
        'Headers': headers,
        'Attachments': attachments,
        'Stats': {
            'email_size_bytes': len(email_message.as_bytes()),
            'total_attachments': len(attachments),
            'unique_urls': len(urls),
            'unique_ips': len(ips)
        }
    }

    # Print human-readable output using tabulate
    print("\nExtracted IP Addresses:\n" + "="*40)
    ip_table = [[item['ip'], item['info']['City'] if item['info'] else '', item['info']['Region'] if item['info'] else '', item['info']['Country'] if item['info'] else '', item['info']['ISP'] if item['info'] else ''] for item in output['IPs']]
    print(tabulate(ip_table, headers=['IP', 'City', 'Region', 'Country', 'ISP']))

    print("\nExtracted URLs:\n" + "="*40)
    url_table = [[item['url'], item['subdomain'], item['domain'], item['suffix']] for item in output['URLs']]
    print(tabulate(url_table, headers=['URL', 'Subdomain', 'Domain', 'Suffix']))

    print("\nExtracted Headers:\n" + "="*40)
    for k, v in output['Headers'].items():
        if isinstance(v, list):
            for line in v:
                print(f"{k}: {line}")
        else:
            print(f"{k}: {v}")

    print("\nExtracted Attachments:\n" + "="*40)
    for att in output['Attachments']:
        print(f"Filename: {att['filename']}, Type: {att['type']}, Size: {att['size_bytes']} bytes")
        print(f"MD5: {att['md5']}, SHA1: {att['sha1']}, SHA256: {att['sha256']}\n")

    print("\nEmail Statistics:\n" + "="*40)
    for k, v in output['Stats'].items():
        print(f"{k}: {v}")

    # Save to JSON if requested
    if args.json:
        with open('output.json', 'w') as f:
            json.dump(output, f, indent=4)
        print('Results saved to output.json')

if __name__ == '__main__':
    main()
