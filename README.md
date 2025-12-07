# Email-Extractor
Email-Extractor is a powerful and efficient tool designed to help cybersecurity professionals, marketers, and researchers quickly gather email addresses from various sources. It ensures accuracy, supports multiple formats, and saves time by automating the extraction process, while maintaining compliance with privacy regulations.
Python tool to extract Indicators of Compromise (IOCs) from email (.eml) files.

## Features

- Extracts IP addresses, URLs, headers, attachments
- Defangs IOCs for safe analysis
- Geolocates IP addresses
- Supports HTML and multiple encodings
- Outputs to console and JSON

## Usage
if the error "error: externally-managed-environment" appears

python3 -m pip install --break-system-packages -r requirements.txt

```bash
cd Email-Extractor-

pip3 install -r requirements.txt

python3 ee.py <path+file> --json

cat output.json 

