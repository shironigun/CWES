# FFUF - Fast Web Fuzzer

## Table of Contents

### **Quick Reference**
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Common Commands](#common-commands)

### **Fuzzing Types**
- [Directory Fuzzing](#directory-fuzzing)
- [Subdomain Discovery](#subdomain-discovery)
- [Parameter Fuzzing](#parameter-fuzzing)
- [Virtual Host Fuzzing](#virtual-host-fuzzing)

### **Advanced Features**
- [Filtering Options](#filtering-options)
- [Multiple Wordlists](#multiple-wordlists)
- [Output Formats](#output-formats)

### **Reference**
- [Wordlists](#wordlists)
- [Common Flags](#common-flags)
- [Examples](#examples)

---

## Installation

```bash
# Ubuntu/Debian
sudo apt install ffuf

# Manual install
go install github.com/ffuf/ffuf@latest
```

## Basic Usage

```bash
# Directory fuzzing
ffuf -w wordlist.txt -u http://target.com/FUZZ

# Subdomain discovery
ffuf -w wordlist.txt -u http://FUZZ.target.com

# Parameter fuzzing
ffuf -w wordlist.txt -u http://target.com/page?FUZZ=test
```

## Directory Fuzzing

### Basic Directory Scan
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ
```

### Filter by Status Code
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -mc 200,301,302,403
```

### Filter by Response Size
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -fs 1234
```

### File Extension Fuzzing
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -e .php,.html,.txt,.js
```

## Subdomain Discovery

### DNS Subdomain Enumeration
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.target.com -mc 200,301,302,403
```

### Subdomain with Custom Port
```bash
ffuf -w wordlist.txt -u https://FUZZ.target.com:8443 -mc 200,301,302,403
```

## Parameter Fuzzing

### GET Parameter Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://target.com/page?FUZZ=test
```

### POST Parameter Fuzzing
```bash
ffuf -w wordlist.txt -u http://target.com/login -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded"
```

### JSON Parameter Fuzzing
```bash
ffuf -w wordlist.txt -u http://target.com/api/endpoint -X POST -d '{"FUZZ":"test"}' -H "Content-Type: application/json"
```

### Cookie Parameter Fuzzing
```bash
ffuf -w wordlist.txt -u http://target.com/page -H "Cookie: FUZZ=test"
```

## Virtual Host Fuzzing

### Basic VHost Discovery
```bash
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fs 1234
```

### VHost with IP Address
```bash
ffuf -w wordlist.txt -u http://192.168.1.100 -H "Host: FUZZ.target.com" -fs 1234
```

## Filtering Options

### Filter by Response Size
```bash
# Filter out specific sizes
ffuf -w wordlist.txt -u http://target.com/FUZZ -fs 1234,5678

# Filter by size range
ffuf -w wordlist.txt -u http://target.com/FUZZ -fs 1000-2000
```

### Filter by Response Words
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -fw 100
```

### Filter by Response Lines
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -fl 50
```

### Filter by Response Time
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -ft 1000ms
```

### Match Patterns
```bash
# Match specific patterns in response
ffuf -w wordlist.txt -u http://target.com/FUZZ -mr "admin\|login\|dashboard"
```

## Multiple Wordlists

### Two Wordlists
```bash
ffuf -w wordlist1.txt:FUZZ1 -w wordlist2.txt:FUZZ2 -u http://target.com/FUZZ1/FUZZ2
```

### Parameter and Value Fuzzing
```bash
ffuf -w params.txt:PARAM -w values.txt:VALUE -u http://target.com/page?PARAM=VALUE
```

## Output Formats

### JSON Output
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -o results.json -of json
```

### CSV Output
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -o results.csv -of csv
```

### HTML Output
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -o results.html -of html
```

## Wordlists

### Directory Discovery
```bash
# Quick
/usr/share/seclists/Discovery/Web-Content/common.txt

# Medium
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Files
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

### Parameter Discovery
```bash
# Common parameters
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# API endpoints
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### Subdomain Discovery
```bash
# Fast
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Comprehensive
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

## Common Flags

| Flag       | Description            | Example                               |
| ---------- | ---------------------- | ------------------------------------- |
| `-u`       | Target URL             | `-u http://target.com/FUZZ`           |
| `-w`       | Wordlist               | `-w wordlist.txt`                     |
| `-X`       | HTTP method            | `-X POST`                             |
| `-d`       | POST data              | `-d "param=value"`                    |
| `-H`       | HTTP header            | `-H "Content-Type: application/json"` |
| `-mc`      | Match status codes     | `-mc 200,301,403`                     |
| `-ms`      | Match response size    | `-ms 1234`                            |
| `-mw`      | Match word count       | `-mw 100`                             |
| `-ml`      | Match line count       | `-ml 50`                              |
| `-mr`      | Match regex            | `-mr "admin\|login"`                  |
| `-fc`      | Filter status codes    | `-fc 404,400`                         |
| `-fs`      | Filter response size   | `-fs 1234`                            |
| `-fw`      | Filter word count      | `-fw 100`                             |
| `-fl`      | Filter line count      | `-fl 50`                              |
| `-fr`      | Filter regex           | `-fr "error\|404"`                    |
| `-ft`      | Filter response time   | `-ft 1000ms`                          |
| `-t`       | Number of threads      | `-t 50`                               |
| `-p`       | Delay between requests | `-p 0.1-2.0`                          |
| `-timeout` | Request timeout        | `-timeout 30`                         |
| `-o`       | Output file            | `-o results.json`                     |
| `-of`      | Output format          | `-of json`                            |
| `-s`       | Silent mode            | `-s`                                  |
| `-v`       | Verbose mode           | `-v`                                  |

## Examples

### Quick Directory Scan
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -mc 200,301,403 -s
```

### Subdomain Discovery with Filtering
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.target.com -mc 200,301,302,403 -fs 1234 -o subdomains.json -of json
```

### API Parameter Fuzzing
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://target.com/api/endpoint -X POST -d '{"FUZZ":"test"}' -H "Content-Type: application/json" -mc 200,400,401,403
```

### Backup File Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://target.com/FUZZ -e .bak,.old,.backup,.tmp -mc 200
```

### Rate-Limited Fuzzing
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ -t 10 -p 0.5-1.0 -timeout 30
```

### Multi-Parameter Testing
```bash
ffuf -w params.txt:PARAM -w values.txt:VALUE -u http://target.com/search?PARAM=VALUE -mc 200,302 -fs 1234
```