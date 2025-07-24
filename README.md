# ShadowX - Advanced XSS Vulnerability Scanner

![ShadowX Banner](https://img.shields.io/badge/ShadowX-XSS%20Scanner-red?style=for-the-badge&logo=security)

**Created by: adce626**

ShadowX is a professional-grade Cross-Site Scripting (XSS) vulnerability scanner inspired by LOXS, designed specifically for comprehensive XSS detection with advanced context-aware analysis, Selenium automation, and false positive reduction.

## 🎯 Features

### Core Capabilities
- **Advanced XSS Detection**: Supports Reflected, DOM-based, Stored, and Blind XSS vulnerabilities
- **Context-Aware Analysis**: Intelligent payload selection based on injection context
- **Selenium Automation**: JavaScript execution analysis using headless Chrome
- **False Positive Reduction**: Combines reflection detection with execution confirmation
- **Multi-Threading**: High-performance concurrent scanning
- **Screenshot Capture**: Automatic evidence collection for successful XSS alerts

### Detection Methods
- Alert popup detection
- DOM modification analysis
- JavaScript error monitoring
- Console log analysis
- Function sink detection
- Blind XSS with webhook integration

### Supported XSS Types
- **Reflected XSS**: Traditional parameter-based injection
- **DOM-based XSS**: Client-side JavaScript vulnerabilities
- **Stored XSS**: Persistent payload detection (basic)
- **Blind XSS**: Out-of-band callback detection

## 🚀 Installation

### Prerequisites
- Python 3.9+
- Google Chrome (latest stable version recommended)
- ChromeDriver (automatically managed by webdriver-manager)

### Quick Installation
```bash
# Method 1: Use requirements file (recommended)
pip install -r requirements_pip.txt

# Method 2: Single command install
pip install selenium==4.15.2 webdriver-manager==4.0.1 rich==13.5.2 colorama==0.4.6 beautifulsoup4==4.12.2 requests==2.31.0 aiohttp==3.9.5 Flask==3.0.3

# Method 3: Automated setup
python setup.py

# Verify installation
python -c "import selenium, requests, rich, colorama, bs4, flask; print('✓ All dependencies installed successfully!')"
```

### Chrome Installation
```bash
# Ubuntu/Debian
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt -f install

# Alternative: Use package manager
sudo apt update && sudo apt install google-chrome-stable
```

### Automated Installation
```bash
# Run the installation script
chmod +x install.sh
./install.sh
```

## 📋 Usage

### Basic Usage
```bash
# Scan a single URL
python main.py --url https://example.com/search?q=test

# Scan multiple URLs from file
python main.py --url-file targets.txt

# Use custom payloads
python main.py --url https://example.com --payloads custom_payloads.txt
```

### Interactive Mode (Recommended)
```bash
# Launch LOXS-style interactive scanner with real-time payload testing
python interactive_loxs.py

# Or use main.py with interactive flag
python main.py --url https://example.com/search?q=test --interactive
python main.py --url https://example.com/search?q=test --mode interactive
```

### Advanced Options
```bash
# Full scan with blind XSS detection
python main.py --url https://example.com --blind --webhook-url https://webhook.site/unique-id

# High-performance scanning
python main.py --url-file targets.txt --threads 15 --timeout 20

# WAF bypass mode with GUI
python main.py --url https://example.com --gui --mode scan

# Generate report from existing data
python main.py --report-only --output-dir ./previous_scan
```

### File Formats

**URLs file (targets.txt):**
```
https://example.com/search?q=test
https://target.com/login?user=admin
https://site.com/contact?name=test&email=test@test.com
```

**Custom payloads file (custom_payloads.txt):**
```
# Your custom XSS payloads (one per line)
<script>alert("MY-XSS")</script>
"><img src=x onerror=alert("MY-XSS")>
';alert('MY-XSS');//
<svg onload=alert("MY-XSS")>
# Lines starting with # are ignored
```

**Using custom payloads:**
```bash
# Interactive mode with custom payloads
python interactive_loxs.py
# (You'll be prompted to specify a custom payloads file)

# Command line with custom payloads
python main.py --url https://example.com/search?q=test --payloads my_payloads.txt --interactive

# Advanced scanning with custom payloads
python main.py --url https://example.com/search?q=test --payloads custom_payloads.txt --mode interactive
```

## 🎯 Features in Detail

### Context-Aware Analysis
ShadowX automatically detects injection contexts and selects appropriate payloads:
- **Script Tag Context**: Breaks out of existing JavaScript
- **HTML Attribute Context**: Escapes attributes and injects handlers
- **HTML Body Context**: Injects tags and handlers
- **Style Context**: CSS-based injection techniques

### False Positive Reduction
- Combines reflection detection with JavaScript execution confirmation
- Analyzes DOM mutations and changes
- Monitors console logs and JavaScript errors
- Captures screenshots as evidence

### Blind XSS Detection
- Webhook integration with services like Interactsh
- Local webhook server option
- Multiple callback methods (XHR, Fetch, Image, DNS)
- Data exfiltration payloads

### Interactive LOXS-Style Interface
ShadowX now features a LOXS-inspired interactive mode that displays real-time payload testing:
- **Live Payload Display**: Each payload is shown as it's being tested
- **Color-Coded Results**: Green for successful XSS, red for failed attempts, yellow for reflected but not executed
- **Real-time Statistics**: Current testing progress with payload counters
- **Vulnerable Parameter Detection**: Immediate notification when XSS is found
- **Professional Terminal Interface**: Rich formatting with progress indicators

**Example Interactive Output:**
```
[001/045] Testing search: <script>alert("XSS")</script> ✓ VULNERABLE - Alert triggered: XSS
[002/045] Testing search: <img src=x onerror=alert("XSS")> ✗ FAILED - Not reflected
[003/045] Testing search: "><script>alert("XSS")</script> ⚠ REFLECTED - No execution
```

### Professional Reporting
- Modern HTML reports with vulnerability cards
- JSON exports for integration
- Screenshot evidence
- Risk assessment and recommendations
