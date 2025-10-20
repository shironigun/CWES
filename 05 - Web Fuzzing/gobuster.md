# Gobuster - Directory & DNS Enumeration Tool

## Table of Contents

### **Quick Reference**
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Common Commands](#common-commands)

### **Enumeration Types**
- [Directory Fuzzing](#directory-fuzzing)
- [DNS Subdomain Discovery](#dns-subdomain-discovery)
- [Virtual Host Discovery](#virtual-host-discovery)

### **Advanced Usage**
- [File Extensions](#file-extensions)
- [Authentication](#authentication)
- [Output Options](#output-options)

### **Reference**
- [Wordlists](#wordlists)
- [Common Flags](#common-flags)
- [Examples](#examples)

---

## Installation

```bash
# Ubuntu/Debian
sudo apt install gobuster

# Manual install
go install github.com/OJ/gobuster/v3@latest
```

## Basic Usage

```bash
# Directory enumeration
gobuster dir -u http://target.com -w wordlist.txt

# DNS subdomain discovery
gobuster dns -d target.com -w wordlist.txt

# Virtual host discovery
gobuster vhost -u http://target.com -w wordlist.txt
```

## Directory Fuzzing

### Basic Directory Scan
```bash
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### With File Extensions
```bash
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt,js
```

### Filter Status Codes
```bash
gobuster dir -u http://target.com -w wordlist.txt -s 200,301,403
```

### Exclude Status Codes
```bash
gobuster dir -u http://target.com -w wordlist.txt -b 404,400
```

## DNS Subdomain Discovery

### Basic DNS Enumeration
```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Custom DNS Server
```bash
gobuster dns -d target.com -w wordlist.txt -r 8.8.8.8
```

### Wildcard Detection
```bash
gobuster dns -d target.com -w wordlist.txt --wildcard
```

## Virtual Host Discovery

### Basic VHost Scan
```bash
gobuster vhost -u http://target.com -w wordlist.txt
```

### Append Domain
```bash
gobuster vhost -u http://target.com -w wordlist.txt --append-domain
```

## File Extensions

### Common Web Extensions
```bash
-x php,html,htm,txt,js,css,xml,json
```

### Backup File Extensions
```bash
-x bak,old,orig,backup,tmp,save
```

### Technology-Specific
```bash
# PHP
-x php,php3,php4,php5,phtml

# ASP.NET
-x asp,aspx,ashx,asmx

# Java
-x jsp,jspa,jspx,do,action
```

## Authentication

### Basic Auth
```bash
gobuster dir -u http://target.com -w wordlist.txt -U username -P password
```

### Custom Headers
```bash
gobuster dir -u http://target.com -w wordlist.txt -H "Authorization: Bearer token123"
```

### Cookies
```bash
gobuster dir -u http://target.com -w wordlist.txt -c "sessionid=abc123"
```

## Output Options

### Save Results
```bash
gobuster dir -u http://target.com -w wordlist.txt -o results.txt
```

### Quiet Output
```bash
gobuster dir -u http://target.com -w wordlist.txt -q
```

### Verbose Output
```bash
gobuster dir -u http://target.com -w wordlist.txt -v
```

## Wordlists

### Directory Discovery
```bash
# Quick scan
/usr/share/seclists/Discovery/Web-Content/common.txt

# Medium scan
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Large scan
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```

### DNS Discovery
```bash
# Fast
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Comprehensive
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

## Common Flags

| Flag        | Description             | Example                |
| ----------- | ----------------------- | ---------------------- |
| `-u`        | Target URL              | `-u http://target.com` |
| `-w`        | Wordlist                | `-w wordlist.txt`      |
| `-x`        | File extensions         | `-x php,html,txt`      |
| `-s`        | Status codes to include | `-s 200,301,403`       |
| `-b`        | Status codes to exclude | `-b 404,400`           |
| `-t`        | Number of threads       | `-t 50`                |
| `-o`        | Output file             | `-o results.txt`       |
| `-q`        | Quiet mode              | `-q`                   |
| `-v`        | Verbose mode            | `-v`                   |
| `--delay`   | Delay between requests  | `--delay 1s`           |
| `--timeout` | Request timeout         | `--timeout 30s`        |

## Examples

### Quick Directory Scan
```bash
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt -q
```

### Comprehensive Subdomain Discovery
```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o subdomains.txt
```

### Recursive Directory Fuzzing
```bash
# First scan
gobuster dir -u http://target.com -w wordlist.txt -o dirs.txt

# Fuzz discovered directories
gobuster dir -u http://target.com/admin -w wordlist.txt -x php,html
```

### Rate-Limited Scanning
```bash
gobuster dir -u http://target.com -w wordlist.txt -t 10 --delay 500ms --timeout 30s
```