# Feroxbuster - Fast Directory Buster

## Table of Contents

### **Quick Reference**
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Common Commands](#common-commands)

### **Core Features**
- [Recursive Scanning](#recursive-scanning)
- [File Extensions](#file-extensions)
- [Filtering Options](#filtering-options)

### **Advanced Features**
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Output Options](#output-options)

### **Reference**
- [Wordlists](#wordlists)
- [Common Flags](#common-flags)
- [Examples](#examples)

---

## Installation

```bash
# Ubuntu/Debian
sudo apt install feroxbuster

# Manual install (latest)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
```

## Basic Usage

```bash
# Basic directory scan
feroxbuster -u http://target.com

# With custom wordlist
feroxbuster -u http://target.com -w wordlist.txt

# With file extensions
feroxbuster -u http://target.com -x php,html,txt
```

## Recursive Scanning

### Basic Recursive Scan
```bash
# Default recursion (4 levels)
feroxbuster -u http://target.com -w wordlist.txt

# Custom recursion depth
feroxbuster -u http://target.com -w wordlist.txt --depth 2

# No recursion
feroxbuster -u http://target.com -w wordlist.txt --no-recursion
```

### Smart Recursion
```bash
# Auto-tune based on response codes
feroxbuster -u http://target.com -w wordlist.txt --auto-tune

# Extract links for further scanning
feroxbuster -u http://target.com -w wordlist.txt --extract-links
```

## File Extensions

### Common Extensions
```bash
feroxbuster -u http://target.com -x php,html,htm,txt,js,css,xml,json
```

### Technology-Specific
```bash
# PHP applications
feroxbuster -u http://target.com -x php,php3,php4,php5,phtml

# ASP.NET applications
feroxbuster -u http://target.com -x asp,aspx,ashx,asmx

# Backup files
feroxbuster -u http://target.com -x bak,old,orig,backup,tmp
```

## Filtering Options

### Status Code Filtering
```bash
# Filter specific status codes
feroxbuster -u http://target.com -C 404,400

# Filter status code ranges
feroxbuster -u http://target.com -C 400-499
```

### Size Filtering
```bash
# Filter by response size
feroxbuster -u http://target.com -S 1234

# Filter size ranges
feroxbuster -u http://target.com -S 1000-2000
```

### Word Count Filtering
```bash
feroxbuster -u http://target.com -W 100
```

### Line Count Filtering
```bash
feroxbuster -u http://target.com -N 50
```

## Authentication

### Basic Authentication
```bash
feroxbuster -u http://target.com -a username:password
```

### Custom Headers
```bash
feroxbuster -u http://target.com -H "Authorization: Bearer token123"
```

### Cookies
```bash
feroxbuster -u http://target.com -H "Cookie: sessionid=abc123"
```

### Multiple Headers
```bash
feroxbuster -u http://target.com -H "Authorization: Bearer token" -H "X-Custom: value"
```

## Rate Limiting

### Thread Control
```bash
# Reduce threads
feroxbuster -u http://target.com -t 10

# Single threaded
feroxbuster -u http://target.com -t 1
```

### Request Delay
```bash
# Add delay between requests
feroxbuster -u http://target.com --rate-limit 100
```

### Timeout Settings
```bash
feroxbuster -u http://target.com --timeout 30
```

## Output Options

### Save Results
```bash
feroxbuster -u http://target.com -o results.txt
```

### JSON Output
```bash
feroxbuster -u http://target.com --json -o results.json
```

### Quiet Mode
```bash
feroxbuster -u http://target.com -q
```

### Verbose Mode
```bash
feroxbuster -u http://target.com -v
```

## Wordlists

### Default Wordlists
```bash
# Feroxbuster includes built-in wordlists
feroxbuster -u http://target.com

# SecLists wordlists
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Recommended Wordlists
```bash
# Quick scan
/usr/share/seclists/Discovery/Web-Content/common.txt

# Medium scan
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# File discovery
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

## Common Flags

| Flag              | Description          | Example                |
| ----------------- | -------------------- | ---------------------- |
| `-u`              | Target URL           | `-u http://target.com` |
| `-w`              | Wordlist             | `-w wordlist.txt`      |
| `-x`              | File extensions      | `-x php,html,txt`      |
| `-t`              | Number of threads    | `-t 50`                |
| `-d`              | Recursion depth      | `-d 3`                 |
| `--depth`         | Max recursion depth  | `--depth 4`            |
| `--no-recursion`  | Disable recursion    | `--no-recursion`       |
| `-C`              | Filter status codes  | `-C 404,400`           |
| `-S`              | Filter response size | `-S 1234`              |
| `-W`              | Filter word count    | `-W 100`               |
| `-N`              | Filter line count    | `-N 50`                |
| `-a`              | Basic auth           | `-a user:pass`         |
| `-H`              | Custom header        | `-H "Auth: token"`     |
| `--rate-limit`    | Requests per second  | `--rate-limit 100`     |
| `--timeout`       | Request timeout      | `--timeout 30`         |
| `-o`              | Output file          | `-o results.txt`       |
| `--json`          | JSON output          | `--json`               |
| `-q`              | Quiet mode           | `-q`                   |
| `-v`              | Verbose mode         | `-v`                   |
| `--extract-links` | Extract links        | `--extract-links`      |
| `--auto-tune`     | Auto-tune scanning   | `--auto-tune`          |

## Examples

### Quick Recursive Scan
```bash
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt --depth 2
```

### Comprehensive Scan with Filtering
```bash
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,js -C 404,400 -S 1234 --extract-links
```

### Authenticated Scanning
```bash
feroxbuster -u http://target.com -w wordlist.txt -H "Authorization: Bearer token123" -H "X-API-Key: key456"
```

### Rate-Limited Scanning
```bash
feroxbuster -u http://target.com -w wordlist.txt -t 10 --rate-limit 50 --timeout 30
```

### Backup File Discovery
```bash
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x bak,old,backup,tmp --no-recursion
```

### API Endpoint Discovery
```bash
feroxbuster -u http://target.com/api -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -x json --extract-links
```

### Stealth Scanning
```bash
feroxbuster -u http://target.com -w wordlist.txt -t 5 --rate-limit 10 -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" -q
```