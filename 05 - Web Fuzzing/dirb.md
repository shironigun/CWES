# Dirb - Web Content Scanner

## Table of Contents

### **Quick Reference**
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Common Commands](#common-commands)

### **Core Features**
- [Directory Scanning](#directory-scanning)
- [File Extensions](#file-extensions)
- [Authentication](#authentication)

### **Advanced Options**
- [Custom Wordlists](#custom-wordlists)
- [Proxy Support](#proxy-support)
- [Output Options](#output-options)

### **Reference**
- [Built-in Wordlists](#built-in-wordlists)
- [Common Flags](#common-flags)
- [Examples](#examples)

---

## Installation

```bash
# Ubuntu/Debian
sudo apt install dirb

# Usually pre-installed on Kali Linux
```

## Basic Usage

```bash
# Basic directory scan
dirb http://target.com

# Custom wordlist
dirb http://target.com wordlist.txt

# With file extensions
dirb http://target.com wordlist.txt -X .php,.html,.txt
```

## Directory Scanning

### Default Scan
```bash
# Uses built-in common.txt wordlist
dirb http://target.com
```

### Custom Wordlist
```bash
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/common.txt
```

### HTTPS Target
```bash
dirb https://target.com
```

### Custom Port
```bash
dirb http://target.com:8080
```

## File Extensions

### Common Extensions
```bash
dirb http://target.com wordlist.txt -X .php,.html,.txt,.js
```

### Technology-Specific
```bash
# PHP applications
dirb http://target.com wordlist.txt -X .php,.php3,.php4,.php5,.phtml

# ASP.NET applications
dirb http://target.com wordlist.txt -X .asp,.aspx,.ashx,.asmx

# Backup files
dirb http://target.com wordlist.txt -X .bak,.old,.orig,.backup,.tmp
```

## Authentication

### Basic Authentication
```bash
dirb http://target.com wordlist.txt -u username:password
```

### Custom Headers
```bash
dirb http://target.com wordlist.txt -H "Authorization: Bearer token123"
```

### Cookies
```bash
dirb http://target.com wordlist.txt -c "sessionid=abc123"
```

### User Agent
```bash
dirb http://target.com wordlist.txt -a "Mozilla/5.0 (compatible; scanner)"
```

## Custom Wordlists

### Built-in Wordlists Location
```bash
ls /usr/share/dirb/wordlists/
```

### Common Built-in Lists
```bash
# Small wordlist
dirb http://target.com /usr/share/dirb/wordlists/small.txt

# Common directories
dirb http://target.com /usr/share/dirb/wordlists/common.txt

# Big wordlist
dirb http://target.com /usr/share/dirb/wordlists/big.txt
```

### SecLists Integration
```bash
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/common.txt
```

## Proxy Support

### HTTP Proxy
```bash
dirb http://target.com wordlist.txt -p http://proxy:8080
```

### SOCKS Proxy
```bash
dirb http://target.com wordlist.txt -p socks://proxy:1080
```

## Output Options

### Save Results
```bash
dirb http://target.com wordlist.txt -o results.txt
```

### Silent Mode
```bash
dirb http://target.com wordlist.txt -S
```

### Verbose Mode
```bash
dirb http://target.com wordlist.txt -v
```

### Show Response Codes
```bash
dirb http://target.com wordlist.txt -w
```

## Built-in Wordlists

### Available Lists
```bash
/usr/share/dirb/wordlists/common.txt          # Most common directories
/usr/share/dirb/wordlists/small.txt           # Small wordlist
/usr/share/dirb/wordlists/big.txt             # Large wordlist
/usr/share/dirb/wordlists/catala.txt          # Catalan words
/usr/share/dirb/wordlists/euskera.txt         # Basque words
/usr/share/dirb/wordlists/extensions_common.txt # Common file extensions
/usr/share/dirb/wordlists/indexes.txt         # Index files
/usr/share/dirb/wordlists/mutations_common.txt # Common mutations
/usr/share/dirb/wordlists/spanish.txt         # Spanish words
/usr/share/dirb/wordlists/stress/             # Stress testing lists
/usr/share/dirb/wordlists/vulns/              # Vulnerability-specific lists
```

## Common Flags

| Flag | Description                     | Example                |
| ---- | ------------------------------- | ---------------------- |
| `-X` | File extensions                 | `-X .php,.html,.txt`   |
| `-u` | Basic auth                      | `-u user:pass`         |
| `-H` | Custom header                   | `-H "Auth: token"`     |
| `-c` | Cookie                          | `-c "session=abc"`     |
| `-a` | User agent                      | `-a "custom agent"`    |
| `-p` | Proxy                           | `-p http://proxy:8080` |
| `-o` | Output file                     | `-o results.txt`       |
| `-S` | Silent mode                     | `-S`                   |
| `-v` | Verbose mode                    | `-v`                   |
| `-w` | Show response codes             | `-w`                   |
| `-f` | Fine tuning                     | `-f`                   |
| `-t` | Don't force ending '/'          | `-t`                   |
| `-z` | Add delay (ms)                  | `-z 1000`              |
| `-N` | Ignore responses with this code | `-N 404`               |
| `-R` | Interactive recursion           | `-R`                   |
| `-r` | Non-recursive                   | `-r`                   |

## Examples

### Quick Common Directory Scan
```bash
dirb http://target.com
```

### Comprehensive Scan with Extensions
```bash
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -X .php,.html,.txt,.js -o results.txt
```

### Authenticated Scanning
```bash
dirb http://target.com /usr/share/dirb/wordlists/common.txt -u admin:password -H "X-Forwarded-For: 127.0.0.1"
```

### Silent Backup File Discovery
```bash
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -X .bak,.old,.backup,.tmp -S
```

### API Endpoint Discovery
```bash
dirb http://target.com/api /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -X .json,.xml
```

### Vulnerability-Specific Scanning
```bash
dirb http://target.com /usr/share/dirb/wordlists/vulns/apache.txt -w
```

### Rate-Limited Scanning
```bash
dirb http://target.com wordlist.txt -z 1000 -S
```

### Proxy-Based Scanning
```bash
dirb http://target.com wordlist.txt -p http://127.0.0.1:8080 -H "X-Scanner: dirb"
```