# 🛡️ SOC Threat Intelligence Scanner Tool

A Python-based CLI tool designed for SOC Analysts and Security Researchers to automate Threat Intelligence lookups across multiple IOC types (IPs, Emails, Phone Numbers, and Website URLs) using real-time API integrations.

--- 

## ✨ Features

- **IP Intelligence:** Queries AbuseIPDB to assess threat confidence scores, ISP, and country location.
- **Email Reputation:** Integrates with AbstractAPI to detect disposable emails, domain age, and suspicious handles.
- **Phone Number Analysis:** Validates carrier details, VOIP detection, and line status.
- **Website URL Scanning:** Submits URLs to URLScan.io for dynamic verdict and malicious request analysis.
- **Automated Logging:** Saves structured scan logs locally with precise timestamps (`scan_log.txt`).
- **Secure Architecture:** Uses environment variables to prevent API key exposure.

---

## 🛠️ Prerequisites

- Python 3.8+
- API Keys from:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AbstractAPI](https://www.abstractapi.com/)
  - [URLScan.io](https://urlscan.io/)

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/soc-threat-scanner.git
   cd soc-threat-scanner


   Create a virtual environment:


python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
Install dependencies:


pip install -r requirements.txt
Configure Environment Variables:
Create a .env file in the root directory and add your API keys:


ABUSEIPDB_API_KEY=your_abuseipdb_key
ABSTRACT_EMAIL_API_KEY=your_abstract_email_key
ABSTRACT_PHONE_API_KEY=your_abstract_phone_key
URLSCAN_API_KEY=your_urlscan_key

💻 Usage
Run the main script:


python main.py
# If python doesn't work on Mac/Linux, use: python3 main.py