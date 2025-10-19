# Information Gathering - Web

**Sequential Pentesting Methodology for Web Application Information Gathering**

## Overview
This guide provides step-by-step methodology for systematically gathering information about web targets during penetration testing. Follow these steps in order to build a comprehensive understanding of the target.

---

## Step 1: Passive Information Gathering (OSINT)

### 1.1 Domain Registration Information
```bash
# Get domain ownership and infrastructure details
whois example.com
whois 192.168.1.1

# Extract key information:
# - Registrar details and dates
# - Administrative contacts
# - Technical contacts  
# - Name servers
# - IP ranges
```

### 1.2 Search Engine Reconnaissance
**Google Dorking for initial intelligence:**

```bash
# Basic site enumeration
site:example.com

# Find login pages and admin panels
site:example.com inurl:login
site:example.com inurl:admin
site:example.com (inurl:login OR inurl:admin OR inurl:signin)

# Discover file types and documents
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx OR filetype:pptx)
site:example.com filetype:sql

# Look for configuration and backup files
site:example.com inurl:config
site:example.com (ext:conf OR ext:cnf OR ext:cfg)
site:example.com inurl:backup
site:example.com (inurl:backup OR inurl:bak OR inurl:old)

# Find error pages and debug info
site:example.com "fatal error"
site:example.com "warning: mysql"
site:example.com "stack trace"

# Directory listings
site:example.com "Index of /"
site:example.com "Directory Listing"
```

### 1.3 Additional OSINT Sources
- Certificate transparency logs (crt.sh)
- Shodan/Censys for exposed services
- Social media and LinkedIn for employee info
- Job postings for technology stack clues

---

## Step 2: DNS Enumeration & Analysis

### 2.1 Basic DNS Information
```bash
# Get all DNS record types
dig example.com ANY
dig example.com A        # IPv4 addresses
dig example.com AAAA     # IPv6 addresses
dig example.com MX       # Mail servers
dig example.com NS       # Name servers
dig example.com TXT      # TXT records
dig example.com SOA      # Start of Authority

# Reverse DNS lookup
dig -x 192.168.1.1
```

### 2.2 Zone Transfer Attempts
```bash
# Attempt zone transfer from each name server
dig @ns1.example.com example.com AXFR
dig @ns2.example.com example.com AXFR

# If successful, you'll get complete DNS zone data
# This reveals all subdomains and internal IPs
```

### 2.3 DNS Security Analysis
- Check for DNSSEC implementation
- Analyze SPF, DKIM, DMARC records
- Look for wildcard DNS configurations

---

## Step 3: Subdomain Discovery & Enumeration

### 3.1 Brute Force Subdomain Discovery
```bash
# DNS brute forcing with dnsenum
dnsenum example.com
dnsenum --dnsserver 8.8.8.8 -f /usr/share/wordlists/subdomains.txt example.com

# Alternative tools
sublist3r -d example.com
amass enum -d example.com
```

### 3.2 Virtual Host Discovery
```bash
# Virtual host brute forcing with gobuster
gobuster vhost -u http://example.com -w /usr/share/wordlists/subdomains.txt
gobuster vhost -u http://192.168.1.1 -w /usr/share/wordlists/subdomains.txt -H "Host: FUZZ.example.com"

# DNS subdomain enumeration
gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt
```

### 3.3 Certificate Transparency Logs
```bash
# Use online tools or APIs:
# - crt.sh
# - certspotter
# - Facebook CT API
```

### 3.4 Post-Discovery Actions
```bash
# Add discovered subdomains to /etc/hosts
echo "192.168.1.1 admin.example.com" >> /etc/hosts
echo "192.168.1.1 api.example.com" >> /etc/hosts

# Test each subdomain for accessibility
for sub in admin api dev staging; do
    curl -I http://$sub.example.com
done
```

---

## Step 4: Port Scanning & Service Discovery

### 4.1 Initial Port Scan
```bash
# Quick TCP scan for web services
nmap -sS -p 80,443,8080,8443,3000,5000,8000,8888 example.com

# Comprehensive web port scan
nmap -sS -p 80-10000 --open example.com

# Service version detection
nmap -sV -p 80,443 example.com
```

### 4.2 HTTP/HTTPS Service Enumeration
```bash
# Check for HTTP vs HTTPS
curl -I http://example.com
curl -I https://example.com

# Check for HTTP security headers
curl -I https://example.com | grep -i "strict-transport\|x-frame\|x-content\|x-xss"
```

---

## Step 5: Web Application Fingerprinting

### 5.1 Technology Stack Identification
```bash
# WhatWeb for comprehensive fingerprinting
whatweb example.com
whatweb -a 3 -v example.com  # Aggressive scan

# Manual header inspection
curl -I http://example.com
curl -IL http://example.com  # Follow redirects

# Look for specific technology indicators:
# - Server headers
# - X-Powered-By headers
# - Set-Cookie formats
# - Error page formats
```

### 5.2 Web Application Firewall Detection
```bash
# WAF detection with wafw00f
wafw00f http://example.com
wafw00f -v http://example.com  # Verbose output

# Manual WAF testing
curl -H "User-Agent: <script>alert(1)</script>" http://example.com
```

### 5.3 CMS and Framework Detection
```bash
# WordPress detection
curl -s http://example.com/wp-content/
curl -s http://example.com/readme.html

# Joomla detection  
curl -s http://example.com/administrator/

# Drupal detection
curl -s http://example.com/CHANGELOG.txt
```

---

## Step 6: Content Discovery & Analysis

### 6.1 Standard File and Directory Discovery
```bash
# Check standard files first
curl -I http://example.com/robots.txt
curl -I http://example.com/sitemap.xml
curl -I http://example.com/.well-known/security.txt
curl -I http://example.com/crossdomain.xml
```

### 6.2 robots.txt Analysis
```bash
# Download and analyze robots.txt
curl http://example.com/robots.txt

# Key information to extract:
# - Disallowed paths (potential targets)
# - Allowed paths
# - Sitemap locations
# - Crawl delays
# - User-agent restrictions
```

### 6.3 .well-known Directory Enumeration
```bash
# RFC 8615 standard endpoints
curl http://example.com/.well-known/security.txt
curl http://example.com/.well-known/change-password
curl http://example.com/.well-known/openid-configuration
curl http://example.com/.well-known/mta-sts.txt

# Complete list at: https://www.iana.org/assignments/well-known-uris/
```

### 6.4 Directory and File Brute Forcing
```bash
# Directory brute forcing
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# File extension brute forcing
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,html,txt,pdf
```

---

## Step 7: Web Crawling & Spidering

### 7.1 Automated Crawling
```bash
# Burp Suite Spider:
# 1. Configure scope to target domain
# 2. Start passive spider from proxy history
# 3. Enable active spider for comprehensive crawling
# 4. Review sitemap for all discovered content

# OWASP ZAP Spider:
zap-cli quick-scan --self-contained http://example.com
# Or use ZAP GUI for manual crawling control
```

### 7.2 Manual Content Analysis
- Review all discovered URLs and parameters
- Identify input points (forms, URL parameters)
- Map application functionality
- Note authentication mechanisms
- Document interesting endpoints

---

## Step 8: Vulnerability Scanning

### 8.1 Web Server Vulnerability Assessment
```bash
# Nikto comprehensive scan
nikto -h http://example.com
nikto -h http://example.com -port 8080

# With proxy for traffic inspection
nikto -h http://example.com -useproxy http://127.0.0.1:8080

# Generate reports
nikto -h http://example.com -o nikto-report.html -Format htm
```

### 8.2 SSL/TLS Configuration Testing
```bash
# SSL certificate information
openssl s_client -connect example.com:443 -servername example.com

# SSL testing with testssl.sh
./testssl.sh example.com

# Check for common SSL vulnerabilities:
# - Weak ciphers
# - SSL/TLS version support
# - Certificate chain issues
# - HSTS implementation
```

---

## Step 9: Information Consolidation & Analysis

### 9.1 Create Target Profile
Document discovered information:
- **Infrastructure**: IP ranges, subdomains, services
- **Technology Stack**: Web server, language, framework, CMS
- **Attack Surface**: Input points, file upload, authentication
- **Security Measures**: WAF, security headers, HTTPS config
- **Potential Vulnerabilities**: Default files, exposed info, misconfigurations

### 9.2 Prioritize Targets
Rank discovered assets by:
1. **Administrative interfaces** (highest priority)
2. **Development/staging environments**
3. **API endpoints**
4. **File upload functionality**
5. **Authentication mechanisms**
6. **Database interfaces**

### 9.3 Plan Next Phase
Based on gathered information, plan:
- **Authentication testing** strategies
- **Input validation** testing priorities  
- **Session management** analysis
- **Authorization** bypass attempts
- **Business logic** testing approach

---

## Step 10: Documentation & Reporting

### 10.1 Organize Findings
Create structured documentation:
```
Target: example.com
Infrastructure:
├── Main Domain: example.com (192.168.1.1)
├── Subdomains: admin.example.com, api.example.com
├── Services: HTTP/80, HTTPS/443
└── Technology: Apache 2.4.41, PHP 7.4, WordPress 5.8

Security Measures:
├── WAF: Cloudflare
├── HTTPS: Valid cert, HSTS enabled
└── Headers: X-Frame-Options, CSP present

Attack Surface:
├── Login: /wp-admin/, /admin/
├── API: /api/v1/
├── File Upload: /upload/
└── Parameters: id, user, search
```

### 10.2 Evidence Collection
- Save all command outputs
- Screenshot interesting findings
- Document exploitation paths
- Note false positives

---

## Quick Reference Commands

```bash
# Essential information gathering workflow
whois example.com
dig example.com ANY
dnsenum example.com  
gobuster vhost -u http://example.com -w /usr/share/wordlists/subdomains.txt
whatweb example.com
wafw00f http://example.com
curl http://example.com/robots.txt
nikto -h http://example.com
```

## Notes
- **Always verify authorization** before starting reconnaissance
- **Use VPN/proxy** for operational security when appropriate
- **Respect rate limits** to avoid detection
- **Document everything** systematically
- **Validate findings** through multiple methods
- **Stay within scope** defined in engagement rules