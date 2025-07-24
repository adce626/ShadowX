# ShadowX - Advanced XSS Vulnerability Scanner

## Overview

ShadowX is a professional-grade Cross-Site Scripting (XSS) vulnerability scanner designed for comprehensive XSS detection with advanced context-aware analysis and Selenium automation. The tool focuses exclusively on XSS vulnerabilities, providing sophisticated detection capabilities with false positive reduction through combined reflection detection and JavaScript execution confirmation.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core Architecture
ShadowX follows a modular architecture with distinct components handling different aspects of XSS detection:

- **Main Application Layer**: Entry point with CLI interface and orchestration
- **Scanner Core**: Primary vulnerability detection engine with Selenium integration
- **Context Engine**: Intelligent payload selection based on injection context
- **Blind XSS Manager**: Webhook-based out-of-band XSS detection
- **Report Generator**: Multi-format report generation (HTML, JSON, text)

### Technology Stack
- **Language**: Python 3.9+
- **Web Automation**: Selenium WebDriver with Chrome/ChromeDriver
- **HTTP Requests**: requests library with retry mechanisms
- **HTML Parsing**: BeautifulSoup4
- **CLI Interface**: Rich library for enhanced terminal output
- **Concurrent Processing**: ThreadPoolExecutor and ProcessPoolExecutor

## Key Components

### 1. XSS Scanner Core (`core/scanner.py`)
The primary scanning engine that:
- Manages Selenium WebDriver instances with headless Chrome
- Implements multi-threaded scanning for performance
- Handles different XSS detection methods (alert popups, DOM changes, console monitoring)
- Captures screenshots of successful XSS executions
- Integrates with context engine for intelligent payload selection

### 2. Context Analysis Engine (`core/context_engine.py`)
Provides intelligent payload selection by:
- Analyzing HTML context where payloads are injected
- Detecting injection points (script tags, attributes, HTML body, etc.)
- Selecting appropriate payloads based on context analysis
- Supporting various contexts: script tags, event handlers, HTML attributes, style blocks

### 3. Blind XSS Manager (`core/blind.py`)
Handles out-of-band XSS detection through:
- Webhook integration (Interactsh, webhook.site, Flask listener)
- Unique payload tracking with session IDs
- Multiple callback methods (image, XHR, fetch, WebSocket, DNS)
- Asynchronous interaction monitoring

### 4. Report Generator (`core/report.py`)
Creates comprehensive reports featuring:
- HTML reports with vulnerability cards and statistics
- JSON reports for programmatic analysis
- Text reports for quick review
- Embedded screenshots and execution evidence
- Vulnerability categorization and risk assessment

### 5. Main Application (`main.py`)
Provides the CLI interface with:
- Rich terminal output with progress bars and colored text
- Command-line argument parsing
- Banner display and branding
- Result orchestration and reporting

## Data Flow

1. **Input Processing**: URLs and payloads are loaded from command-line arguments or files
2. **Context Analysis**: Each target URL is analyzed to determine injection context
3. **Payload Selection**: Context engine selects appropriate payloads for each injection point
4. **Concurrent Scanning**: Multiple threads execute XSS tests using Selenium
5. **Vulnerability Detection**: Scanner monitors for alerts, DOM changes, and console activity
6. **Evidence Collection**: Screenshots and execution proof are captured
7. **Result Aggregation**: All findings are collected and deduplicated
8. **Report Generation**: Comprehensive reports are generated in multiple formats

## External Dependencies

### Required Python Packages
- **selenium**: Web automation and JavaScript execution
- **webdriver-manager**: Automatic ChromeDriver management
- **requests**: HTTP client with retry mechanisms
- **beautifulsoup4**: HTML parsing and analysis
- **rich**: Enhanced CLI output and formatting
- **colorama**: Cross-platform colored terminal output

### System Dependencies
- **Google Chrome**: Version 114.0.5735.198 (64-bit) specified
- **ChromeDriver**: Automatically managed via webdriver-manager

### Optional External Services
- **Webhook services**: For blind XSS detection (Interactsh, webhook.site)
- **Flask listener**: Alternative webhook implementation

## Deployment Strategy

### Development Setup
- Python 3.9+ environment with pip package management
- Chrome browser installation with matching ChromeDriver
- Directory structure with core modules and assets
- Development testing with local webhook listeners

### Production Considerations
- Multi-threading configuration based on target capacity
- Screenshot storage management for evidence retention
- Report output directory organization
- Chrome browser version compatibility maintenance
- Webhook service reliability for blind XSS detection

### Configuration Options
- Headless browser operation for server environments
- Configurable timeouts and thread counts
- Flexible payload loading from external files
- Customizable output directories for reports and screenshots
- Session management for concurrent scanning operations

The architecture prioritizes modularity, allowing easy extension of detection methods, payload types, and report formats while maintaining performance through concurrent processing and intelligent context analysis.