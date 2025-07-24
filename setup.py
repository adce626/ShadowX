#!/usr/bin/env python3
"""
ShadowX Setup Script
Created by: adce626
Quick dependency installation and verification
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def install_dependencies():
    """Install Python dependencies"""
    packages = [
        "selenium==4.15.2",
        "webdriver-manager==4.0.1", 
        "rich==13.5.2",
        "colorama==0.4.6",
        "beautifulsoup4==4.12.2",
        "requests==2.31.0",
        "aiohttp==3.9.5",
        "Flask==3.0.3"
    ]
    
    command = f"pip install {' '.join(packages)}"
    return run_command(command, "Installing ShadowX dependencies")

def verify_installation():
    """Verify all dependencies are installed correctly"""
    print("🧪 Verifying installation...")
    
    try:
        import selenium
        import requests
        import rich
        import colorama
        import bs4
        import flask
        import webdriver_manager
        import aiohttp
        
        print("✅ All dependencies verified successfully!")
        print("🎯 ShadowX is ready to use!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def main():
    """Main setup function"""
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                    ShadowX Quick Setup                       ║")
    print("║                   Created by: adce626                        ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 9):
        print("❌ Python 3.9+ is required")
        sys.exit(1)
    
    print(f"✅ Python {python_version.major}.{python_version.minor} detected")
    print()
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Setup failed during dependency installation")
        sys.exit(1)
    
    print()
    
    # Verify installation
    if not verify_installation():
        print("❌ Setup failed during verification")
        sys.exit(1)
    
    print()
    print("🚀 Setup complete! You can now run:")
    print("   python main.py --url https://example.com")
    print("   python interactive.py  # For interactive mode")

if __name__ == "__main__":
    main()