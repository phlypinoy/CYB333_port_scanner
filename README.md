# Port Scanner

A Python-based network port scanning tool developed for CYB333. This educational tool demonstrates network security concepts and port scanning techniques with built-in ethical scanning guidelines.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)

## Overview

This port scanner is a command-line application that identifies open ports on specified hosts. It includes rate-limiting, authorized target lists, and comprehensive error handling to demonstrate responsible network security practices.

## Features

### Core Functionality
- ✅ **Port Scanning**: Scan single ports, multiple ports, or port ranges
- ✅ **Target Selection**: Interactive menu with pre-authorized targets
- ✅ **Host Validation**: Automatic hostname/IP address resolution
- ✅ **Progress Tracking**: Real-time scan progress with time estimates
- ✅ **Results Summary**: Detailed reports of open/closed ports

### Security & Ethics
- 🔒 **Rate Limiting**: Configurable delays between port attempts (100ms default)
- 🔒 **Scan Limits**: Maximum 1000 ports per scan to prevent abuse
- 🔒 **Authorized Targets**: Restricted to localhost and authorized test servers
- 🔒 **User Warnings**: Alerts for large scans and unreachable hosts

### Technical Features
- 🛠️ **Flexible Port Input**: Supports individual ports (22,80,443), ranges (1-100), or common ports
- 🛠️ **Error Handling**: Comprehensive exception handling and validation
- 🛠️ **Type Safety**: Full type hints for better code reliability

### User Experience
- 📊 **Interactive Menu**: User-friendly command-line interface
- 📊 **Detailed Statistics**: Scan time and port counts
- 📊 **Graceful Exit**: Clean handling of interrupts and errors

## Requirements

### System Requirements
- **Python**: 3.12 or higher

### Python Dependencies
This project uses only Python standard library modules:
- `socket` - Network communication
- `sys` - System-specific parameters
- `time` - Time delays and measurements
- `typing` - Type hints

**No external packages required** 

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/phlypinoy/CYB333_port_scanner.git
   cd CYB333_port_scanner
   ```

2. **Verify Python version**
   ```bash
   python3 --version
   # Should be Python 3.12 or higher
   ```

3. **Make the script executable** (Linux/macOS)
   ```bash
   chmod +x main.py
   ```

## Usage

### Basic Usage

Run the port scanner:
```bash
python3 main.py
```

