#!/bin/bash
# ShadowX Installation Script
# Created by: adce626
# Automated installation for ShadowX XSS Scanner

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    ShadowX Installation                      ║"
echo "║                   Created by: adce626                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check Python version
echo "🔍 Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python 3 detected"
echo

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install selenium==4.15.2 webdriver-manager==4.0.1 rich==13.5.2 colorama==0.4.6 beautifulsoup4==4.12.2 requests==2.31.0 aiohttp==3.9.5 Flask==3.0.3

if [ $? -eq 0 ]; then
    echo "✅ Python dependencies installed successfully"
else
    echo "❌ Failed to install Python dependencies"
    exit 1
fi
echo

# Check if Chrome is installed
echo "🔍 Checking for Google Chrome..."
if command -v google-chrome &> /dev/null || command -v chromium-browser &> /dev/null; then
    echo "✅ Chrome/Chromium detected"
else
    echo "⚠️  Chrome not detected. Installing..."
    
    # Detect OS and install Chrome accordingly
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            # Ubuntu/Debian
            wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
            echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
            sudo apt update
            sudo apt install -y google-chrome-stable
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            sudo yum install -y wget
            wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
            sudo yum localinstall -y google-chrome-stable_current_x86_64.rpm
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "🍎 macOS detected. Please install Chrome manually from https://www.google.com/chrome/"
    fi
fi
echo

# Verify installation
echo "🧪 Verifying installation..."
python3 -c "
import selenium
import requests
import rich
import colorama
import bs4
import flask
print('✅ All dependencies verified successfully!')
print('🎯 ShadowX is ready to use!')
"

if [ $? -eq 0 ]; then
    echo
    echo "🚀 Installation complete!"
    echo
    echo "Usage examples:"
    echo "  python main.py --url https://example.com"
    echo "  python interactive.py  # For interactive mode"
    echo
else
    echo "❌ Installation verification failed"
    exit 1
fi