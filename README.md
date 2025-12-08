# Email Extractor (EE)

A powerful and modern tool for advanced **phishing email analysis**, IOC extraction, geolocation, attachment inspection, and automated security enrichment using external APIs.

---

## ✨ Features

* 📌 Extracts **IP addresses**, **URLs**, **email headers**, **domains**, and **attachments**
* 🧹 Automatically **defangs** IOCs for safe sharing
* 🌍 Performs **IP geolocation**, ASN lookup, and DNS resolution
* 📨 Supports `.eml`, HTML, text, multi-encoding parsing
* 🧪 Analyzes attachments: PDF, DOCX, OLE, HTML
* ⚡ Async enrichment via **VirusTotal** + **AbuseIPDB**
* 💾 Output to **console** and **JSON**
* 🎨 Colorized terminal output
* 🔄 Supports multiple files at once
* 🖱 Interactive mode for step-by-step processing (`--interactive`)

---

## 📦 Installation

### Clone Repository

```bash
git clone https://github.com/1Sam3/Email-Extractor-.git
cd Email-Extractor-
```

### Install Dependencies

#### Normal installation:

```bash
pip3 install -r requirements.txt
```

#### If you see this error:

`error: externally-managed-environment`
Use:

```bash
python3 -m pip install --break-system-packages -r requirements.txt
```

---

## ▶️ Usage

### Basic Scan

```bash
python3 ee.py <path/to/email.eml>
```

### Output results to JSON

```bash
python3 ee.py <email.eml> --json
```

### Scan multiple files

```bash
python3 ee.py email1.eml email2.eml --json
```

### Interactive Mode

Run step-by-step interactive processing for emails:

```bash
python3 ee.py --interactive
```

### View JSON results

```bash
cat output.json
```

### Use VirusTotal + AbuseIPDB (async enrichment)

```bash
python3 ee.py sample.eml --vt-key YOUR_VT_KEY --abuse-key YOUR_ABUSE_KEY --json
```

---

## 🔑 API Keys (Optional but Recommended)

* **VirusTotal**: for URL/IP/domain reputation
* **AbuseIPDB**: for IP abuse reports

Provide them via command line:

```bash
--vt-key <KEY> --abuse-key <KEY>
```

---

## 📁 File Types Supported

* `.eml`
* `.txt`
* `.html`
* `PDF`, `DOCX`, `OLE` attachments

---

## 🛠 Requirements

Installed automatically via `requirements.txt`:

```
requests
aiohttp
tldextract
tabulate
chardet
pdfminer.six
python-docx
oertools
pandas
tqdm
colorama
dnspython
dkimpy
pyspf
beautifulsoup4
lxml
```

---

## 🧩 Example Commands

Extract URLs only:

```bash
python3 ee.py email.eml --urls
```

Extract attachments:

```bash
python3 ee.py email.eml --extract
```

Verbose mode:

```bash
python3 ee.py email.eml -v
```

Interactive mode:

```bash
python3 ee.py --interactive
```

---

## 📜 License

MIT

---


