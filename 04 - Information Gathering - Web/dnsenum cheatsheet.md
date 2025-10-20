# dnsenum - Complete DNS Enumeration Cheatsheet

*Comprehensive DNS reconnaissance and subdomain discovery tool*

---

## Overview

**dnsenum** is a powerful, versatile command-line DNS enumeration tool written in Perl. It's designed for comprehensive DNS reconnaissance during penetration testing and security assessments. The tool automates multiple DNS discovery techniques in a single command, making it essential for information gathering phases.

### Key Capabilities

**DNS Record Enumeration**
- Retrieves A, AAAA, NS, MX, TXT, SOA, and PTR records
- Provides comprehensive DNS configuration overview
- Identifies mail servers, name servers, and service records

**Zone Transfer Attempts**
- Automatically attempts AXFR zone transfers from discovered name servers
- Tests all discovered name servers for misconfigurations
- Can reveal complete DNS zone data including internal subdomains

**Subdomain Brute-Force Discovery**
- Dictionary-based subdomain enumeration using wordlists
- Supports custom wordlists for targeted discovery
- Multithreaded scanning for improved performance

**Google Scraping**
- Scrapes Google search results for additional subdomains
- Finds subdomains not listed in DNS records directly
- Discovers publicly indexed but unlisted subdomains

**Reverse DNS Lookups**
- Performs reverse DNS queries on discovered IP addresses
- Identifies other domains hosted on the same servers
- Reveals shared hosting environments and related domains

**WHOIS Integration**
- Automatic WHOIS queries for domain registration information
- Gathers ownership and administrative contact details
- Provides network registration data


---

## Installation

### Kali Linux / Debian / Ubuntu
```bash
# Usually pre-installed on Kali Linux
apt-get install dnsenum

# Verify installation
dnsenum --version
```

### Manual Installation
```bash
# Clone from GitHub
git clone https://github.com/fwaeytens/dnsenum.git
cd dnsenum
chmod +x dnsenum.pl

# Install dependencies
cpan Net::IP Net::DNS Net::Netmask XML::Writer String::Random
```

---

## Basic Syntax & Usage

### Minimum Command
```bash
dnsenum <target_domain>
```

### Recommended Full Enumeration
```bash
dnsenum --enum <target_domain>
```

---

## Command Line Options

### Core Options
| Option       | Description                           | Example                      |
| ------------ | ------------------------------------- | ---------------------------- |
| `<domain>`   | Target domain to enumerate            | `dnsenum example.com`        |
| `--enum`     | Enable full enumeration (recommended) | `dnsenum --enum example.com` |
| `-h, --help` | Display help information              | `dnsenum -h`                 |
| `--version`  | Show version information              | `dnsenum --version`          |

### DNS Configuration
| Option                 | Description             | Example                                   |
| ---------------------- | ----------------------- | ----------------------------------------- |
| `--dnsserver <server>` | Use specific DNS server | `dnsenum --dnsserver 8.8.8.8 example.com` |
| `--timeout <seconds>`  | DNS query timeout       | `dnsenum --timeout 10 example.com`        |

### Subdomain Discovery
| Option                                | Description                     | Example                                                      |
| ------------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| `-f <wordlist>`                       | Use custom subdomain wordlist   | `dnsenum -f /usr/share/wordlists/subdomains.txt example.com` |
| `-u <a,aaaa,cname,mx,ns,ptr,soa,txt>` | Specify record types to query   | `dnsenum -u a,mx,ns example.com`                             |
| `-s <number>`                         | Maximum subdomains to enumerate | `dnsenum -s 100 example.com`                                 |

### Performance & Threading  
| Option         | Description                       | Example                     |
| -------------- | --------------------------------- | --------------------------- |
| `-t <threads>` | Number of threads (default: 5)    | `dnsenum -t 15 example.com` |
| `-p <pages>`   | Pages to process in Google search | `dnsenum -p 10 example.com` |
| `-d <delay>`   | Delay between queries (seconds)   | `dnsenum -d 2 example.com`  |

### Network Discovery
| Option             | Description                | Example                                  |
| ------------------ | -------------------------- | ---------------------------------------- |
| `-r`               | Enable reverse DNS lookups | `dnsenum -r example.com`                 |
| `--private`        | Show private IP addresses  | `dnsenum --private example.com`          |
| `--subfile <file>` | Write subdomains to file   | `dnsenum --subfile subs.txt example.com` |

### Output & Reporting
| Option      | Description                | Example                              |
| ----------- | -------------------------- | ------------------------------------ |
| `-o <file>` | Output results to XML file | `dnsenum -o results.xml example.com` |
| `-v`        | Verbose output             | `dnsenum -v example.com`             |

### Control Options
| Option        | Description              | Example                           |
| ------------- | ------------------------ | --------------------------------- |
| `--noreverse` | Skip reverse DNS lookups | `dnsenum --noreverse example.com` |
| `--noping`    | Skip host ping checks    | `dnsenum --noping example.com`    |
| `--nocolor`   | Disable colored output   | `dnsenum --nocolor example.com`   |

---

## Practical Examples

### Basic Reconnaissance
```bash
# Quick basic enumeration
dnsenum example.com

# Basic enumeration with specific DNS server
dnsenum --dnsserver 1.1.1.1 example.com

# Verbose basic enumeration
dnsenum -v example.com
```

### Comprehensive Enumeration
```bash
# Full enumeration (recommended approach)
dnsenum --enum example.com

# Full enumeration with custom wordlist
dnsenum --enum -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt example.com

# Full enumeration with increased threading
dnsenum --enum -t 20 example.com
```

### Targeted Subdomain Discovery
```bash
# Brute-force with custom wordlist
dnsenum -f /usr/share/wordlists/dirb/common.txt example.com

# Limit subdomain enumeration
dnsenum -f wordlist.txt -s 50 example.com

# Subdomain discovery without reverse lookups
dnsenum --noreverse -f subdomains.txt example.com
```

### Network Range Analysis
```bash
# Enable reverse DNS lookups for discovered IPs
dnsenum -r example.com

# Show private IP addresses in results
dnsenum --private -r example.com

# Reverse lookup without subdomain brute-force
dnsenum -r --noreverse example.com
```

### Performance Optimization
```bash
# High-speed scanning (use with caution)
dnsenum --enum -t 30 -d 0.5 example.com

# Stealth scanning with delays
dnsenum --enum -t 3 -d 3 example.com

# Skip ping checks for faster scanning
dnsenum --enum --noping example.com
```

### Output and Reporting
```bash
# Save results to XML file
dnsenum --enum -o dnsenum_results.xml example.com

# Save subdomains to separate file
dnsenum --enum --subfile discovered_subdomains.txt example.com

# Generate both XML and subdomain list
dnsenum --enum -o full_results.xml --subfile subdomains.txt example.com
```

### Advanced Combinations
```bash
# Comprehensive scan with all features
dnsenum --enum -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        --dnsserver 8.8.8.8 -t 15 -p 5 -o complete_scan.xml \
        --subfile subdomains.txt example.com

# Stealth comprehensive scan
dnsenum --enum --noping -d 2 -t 5 \
        -f /usr/share/wordlists/dirb/common.txt \
        --dnsserver 1.1.1.1 example.com

# Fast scan for quick results
dnsenum --noreverse --noping -t 20 \
        -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-1000.txt \
        example.com
```

---

## Understanding dnsenum Output

### Standard Output Sections

#### 1. Host Information
```
Host's addresses:
__________________
example.com.                     300      IN    A        93.184.216.34
```
- Shows primary domain IP addresses
- Displays TTL (Time To Live) values
- Lists both IPv4 (A) and IPv6 (AAAA) records

#### 2. Name Servers  
```
Name Servers:
______________
ns1.example.com.                 172800   IN    A        199.43.135.53
ns2.example.com.                 172800   IN    A        199.43.133.53
```
- Lists authoritative name servers
- Shows name server IP addresses
- Critical for zone transfer attempts

#### 3. Mail Servers
```
Mail (MX) Servers:
___________________
                                 300      IN    MX       10 mail.example.com.
mail.example.com.                300      IN    A        93.184.216.35
```
- Shows mail exchange servers
- Displays priority values (lower = higher priority)
- Resolves MX hostnames to IP addresses

#### 4. Zone Transfer Results
```
Trying Zone Transfers and getting Bind Versions:
_________________________________________________
Trying Zone Transfer for example.com on ns1.example.com ... 
AXFR record query failed: Transfer failed
```
- **Success**: Complete zone data with all subdomains
- **Failure**: "Transfer failed" or "Connection refused"
- **Partial**: Some records may be revealed

#### 5. Subdomain Brute-Force Results
```
Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________
admin.example.com.               300      IN    A        93.184.216.36
api.example.com.                 300      IN    A        93.184.216.37
www.example.com.                 300      IN    CNAME    example.com.
```
- Lists discovered subdomains
- Shows record types (A, CNAME, etc.)
- Includes TTL and IP resolution

#### 6. Reverse DNS Lookups
```
Performing reverse lookup on 32 ip addresses:
______________________________________________
36.216.184.93.in-addr.arpa.      86400    IN    PTR      admin.example.com.
37.216.184.93.in-addr.arpa.      86400    IN    PTR      api.example.com.
```
- Reveals additional domains on discovered IPs
- Shows shared hosting environments
- May discover related domains

### XML Output Structure
```xml
<?xml version="1.0"?>
<document>
    <host>
        <name>example.com</name>
        <address>93.184.216.34</address>
    </host>
    <subdomains>
        <subdomain>
            <name>admin.example.com</name>
            <address>93.184.216.36</address>
        </subdomain>
    </subdomains>
</document>
```

### Key Indicators in Output

**Successful Findings**
- ✅ Multiple subdomains discovered
- ✅ Zone transfer successful
- ✅ Reverse lookups reveal additional domains
- ✅ Mail servers and name servers identified

**Security Concerns**
- ⚠️ Zone transfer allowed (major security issue)
- ⚠️ Development/staging subdomains exposed
- ⚠️ Administrative interfaces discovered
- ⚠️ Internal naming conventions revealed

---

## Wordlists for Subdomain Discovery

### Default Wordlist Location
```bash
# dnsenum default wordlist
/usr/share/dnsenum/dns.txt

# Common wordlist locations
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Custom Wordlist Creation
```bash
# Create targeted subdomain wordlist
echo -e "admin\napi\ndev\nstaging\ntest\nwww\nmail\nftp" > custom_subs.txt

# Combine multiple wordlists
cat /usr/share/wordlists/dirb/common.txt \
    /usr/share/wordlists/dirb/big.txt > combined_subs.txt

# Use with dnsenum
dnsenum -f custom_subs.txt example.com
```

### Recommended Wordlists
**Small/Fast (< 1000 entries)**
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-1000.txt`

**Medium (1000-5000 entries)**  
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`

**Large/Comprehensive (> 5000 entries)**
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

---

## Best Practices & Operational Tips

### Reconnaissance Strategy
```bash
# Phase 1: Quick reconnaissance
dnsenum example.com

# Phase 2: Comprehensive enumeration
dnsenum --enum -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt example.com

# Phase 3: Targeted discovery based on findings
dnsenum -f custom_targeted_wordlist.txt example.com
```

### Performance Optimization
**For Speed:**
- Increase threads: `-t 20`
- Skip unnecessary checks: `--noping --noreverse`
- Use smaller wordlists
- Reduce delay: `-d 0.5`

**For Stealth:**
- Lower thread count: `-t 3`  
- Increase delays: `-d 3`
- Use alternative DNS servers: `--dnsserver 8.8.8.8`
- Smaller batch sizes

### Error Handling & Troubleshooting

#### Common Issues
```bash
# DNS resolution failures
# Solution: Try different DNS servers
dnsenum --dnsserver 1.1.1.1 example.com
dnsenum --dnsserver 8.8.8.8 example.com

# Rate limiting detected
# Solution: Reduce threads and increase delays
dnsenum -t 5 -d 2 example.com

# Network connectivity issues
# Solution: Test basic connectivity first
nslookup example.com
dig example.com
```

#### Verification Commands
```bash
# Verify discovered subdomains
nslookup subdomain.example.com
dig subdomain.example.com A

# Test zone transfer manually
dig @ns1.example.com example.com AXFR

# Validate results with other tools
sublist3r -d example.com
amass enum -d example.com
```

### Legal and Ethical Considerations

**Before Running dnsenum:**
- ✅ Ensure proper authorization for target domain
- ✅ Verify scope includes DNS enumeration  
- ✅ Check rate limiting policies
- ✅ Document all activities

**Operational Security:**
- Use VPN when appropriate
- Rotate DNS servers to avoid detection
- Monitor for defensive responses
- Respect target infrastructure

### Integration with Other Tools

#### Pre-dnsenum Reconnaissance
```bash
# Basic domain information
whois example.com
nslookup example.com  
dig example.com ANY
```

#### Post-dnsenum Analysis
```bash
# Port scanning discovered subdomains
nmap -sS -p 80,443 $(cat subdomains.txt)

# Web application discovery
for sub in $(cat subdomains.txt); do
    curl -I http://$sub
    curl -I https://$sub
done

# Further enumeration
gobuster dir -u http://subdomain.example.com -w /usr/share/wordlists/dirb/common.txt
```

---

## Advanced Techniques

### Batch Processing Multiple Domains
```bash
# Create domain list
echo -e "example1.com\nexample2.com\nexample3.com" > domains.txt

# Process each domain
while read domain; do
    echo "Processing $domain"
    dnsenum --enum -o "${domain}_results.xml" "$domain"
done < domains.txt
```

### Custom DNS Server Configuration
```bash
# Use multiple DNS servers for redundancy
dnsenum --dnsserver 8.8.8.8 example.com > results_google.txt
dnsenum --dnsserver 1.1.1.1 example.com > results_cloudflare.txt  
dnsenum --dnsserver 208.67.222.222 example.com > results_opendns.txt

# Compare results for completeness
diff results_google.txt results_cloudflare.txt
```

### Automated Reporting
```bash
#!/bin/bash
# dnsenum automation script
TARGET="$1"
OUTPUT_DIR="dnsenum_$(date +%Y%m%d_%H%M)"

mkdir -p "$OUTPUT_DIR"

# Comprehensive scan
dnsenum --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        -o "$OUTPUT_DIR/full_results.xml" \
        --subfile "$OUTPUT_DIR/subdomains.txt" \
        "$TARGET"

# Generate summary
echo "DNS Enumeration Summary for $TARGET" > "$OUTPUT_DIR/summary.txt"
echo "Scan completed: $(date)" >> "$OUTPUT_DIR/summary.txt"
echo "Subdomains discovered: $(wc -l < "$OUTPUT_DIR/subdomains.txt")" >> "$OUTPUT_DIR/summary.txt"
```

---

## References & Additional Resources

### Official Documentation
- [dnsenum GitHub Repository](https://github.com/fwaeytens/dnsenum)
- [Kali Linux Tools: dnsenum](https://tools.kali.org/information-gathering/dnsenum)
- [dnsenum Manual Page](https://www.kali.org/tools/dnsenum/)

### Related Tools & Alternatives
- **sublist3r**: Python-based subdomain enumeration
- **amass**: Advanced DNS enumeration and network mapping  
- **gobuster**: Fast directory/file & DNS busting tool
- **fierce**: DNS reconnaissance tool
- **dnsrecon**: DNS enumeration script

### Wordlist Resources
- [SecLists DNS Discovery](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [Subdomains Top 1 Million](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [DNSEnum Default Wordlist](https://github.com/fwaeytens/dnsenum/blob/master/dns.txt)

---

*Last Updated: October 20, 2025*  
*Version: 2.0 - Enhanced dnsenum Cheatsheet*
