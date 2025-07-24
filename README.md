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
- Google Chrome 114.0.5735.198 (64-bit)
- ChromeDriver (automatically managed by webdriver-manager)

### Chrome Installation
```bash
# Ubuntu/Debian
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt -f install

# Or use the auto-managed ChromeDriver (recommended)
