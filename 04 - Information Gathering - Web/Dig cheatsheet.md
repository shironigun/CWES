
# Dig Cheatsheet - DNS Lookup Tool

*Complete reference for DNS reconnaissance using dig (Domain Information Groper)*

---

## Overview

**dig** (Domain Information Groper) is the most powerful and flexible DNS lookup tool for DNS troubleshooting, reconnaissance, and analysis. It's the go-to tool for DNS queries during penetration testing and network analysis, offering precise control over query types and output formatting.

### Key Features
- **Flexible query options** - Supports all DNS record types
- **Multiple output formats** - From verbose to script-friendly
- **DNS server specification** - Query any DNS server directly
- **Trace functionality** - Debug DNS resolution paths
- **DNSSEC support** - Validate DNS security extensions
- **Batch processing** - Efficient for automation and scripting

---

## Installation & Availability

```bash
# Usually pre-installed on most Linux distributions
which dig

# Install on Debian/Ubuntu if missing
sudo apt-get install dnsutils

# Install on CentOS/RHEL/Fedora
sudo yum install bind-utils     # CentOS/RHEL
sudo dnf install bind-utils     # Fedora

# Verify installation
dig -v
```

---

## Basic Syntax

```bash
dig [@server] [domain] [record_type] [options]
```

### Essential Commands

```bash
# Basic domain lookup (A record)
dig domain.com

# Query specific DNS server
dig @8.8.8.8 domain.com

# Query specific record type
dig domain.com MX

# Reverse DNS lookup
dig -x 93.184.216.34

# Multiple record types
dig domain.com A MX NS
```

---

## DNS Record Types Reference

| Record    | Command                                 | Description                         | Use Case                       |
| --------- | --------------------------------------- | ----------------------------------- | ------------------------------ |
| **A**     | `dig domain.com A`                      | IPv4 address mapping                | Primary domain resolution      |
| **AAAA**  | `dig domain.com AAAA`                   | IPv6 address mapping                | IPv6 connectivity testing      |
| **NS**    | `dig domain.com NS`                     | Name server records                 | Find authoritative servers     |
| **MX**    | `dig domain.com MX`                     | Mail exchange servers               | Email infrastructure mapping   |
| **TXT**   | `dig domain.com TXT`                    | Text records                        | SPF, DKIM, domain verification |
| **CNAME** | `dig subdomain.domain.com CNAME`        | Canonical name alias                | Alias resolution               |
| **SOA**   | `dig domain.com SOA`                    | Start of Authority                  | Zone information and serial    |
| **SRV**   | `dig _service._protocol.domain.com SRV` | Service records                     | Service discovery              |
| **PTR**   | `dig -x IP_ADDRESS`                     | Reverse DNS lookup                  | IP to hostname resolution      |
| **CAA**   | `dig domain.com CAA`                    | Certificate Authority Authorization | SSL certificate policies       |
| **ANY**   | `dig domain.com ANY`                    | All available records               | Comprehensive enumeration      |

---

## Output Control Options

### Clean Output for Scripts
```bash
# Show only the answer (most common for scripts)
dig +short domain.com

# Show only answer section with details
dig domain.com +noall +answer

# Show only authority section
dig domain.com +noall +authority

# Show only additional section
dig domain.com +noall +additional

# Combine sections
dig domain.com +noall +answer +authority
```

### Detailed Output Control
```bash
# Remove all sections then add specific ones
dig domain.com +noall +answer +stats

# Show statistics only
dig domain.com +noall +stats

# Show comments and questions
dig domain.com +noall +question +answer

# Suppress specific sections
dig domain.com +noquestion +noauthority +noadditional
```

---

## Common Record Types

| Record | Command Example        | Description                      |
| ------ | ---------------------- | -------------------------------- |
| A      | `dig domain.com A`     | IPv4 address                     |
| AAAA   | `dig domain.com AAAA`  | IPv6 address                     |
| NS     | `dig domain.com NS`    | Authoritative name servers       |
| SOA    | `dig domain.com SOA`   | Start of Authority (zone info)   |
| MX     | `dig domain.com MX`    | Mail exchange servers            |
| TXT    | `dig domain.com TXT`   | Text records (SPF, verification) |
| CNAME  | `dig domain.com CNAME` | Canonical name / alias           |
| SRV    | `dig domain.com SRV`   | Service records                  |
| ANY    | `dig domain.com ANY`   | All records (often rate-limited) |

---

## Zone Transfer (AXFR)

```sh
dig @ns1.example.com example.com AXFR
```
> **Note:** If allowed, the server returns the full zone file. If not, you’ll see "Transfer failed" or nothing. Do not attempt against third-party domains without permission.

---

## Interpreting Output

- `;; ANSWER SECTION:` — The records returned (what you usually want)
- `;; AUTHORITY SECTION:` — Nameservers for the zone
- `;; ADDITIONAL SECTION:` — A/AAAA records for nameservers or extra data

**Header Flags:**

| Flag     | Meaning               |
| -------- | --------------------- |
| aa       | Authoritative answer  |
| ad       | DNSSEC authenticated  |
| qr       | Query response        |
| NOERROR  | Query successful      |
| NXDOMAIN | Domain does not exist |
| SERVFAIL | Server failure        |

---

## Advanced Usage & Examples

```sh
# Query for a specific record type and server, show only answer
dig @1.1.1.1 example.com TXT +short

# Trace DNS resolution for a subdomain
dig sub.example.com +trace

# Check DNSSEC validation
dig example.com +dnssec +short

# Reverse lookup for a subnet
for ip in {1..5}; do dig -x 192.168.1.$ip +short; done
```

---

## Troubleshooting

- If you get no answer, try a different DNS server (e.g., `@1.1.1.1` or `@8.8.8.8`).
- Use `+tcp` if you suspect UDP truncation or firewall issues.
- Use `+trace` to debug DNS resolution path issues.

---

## Tips

- Use `+short` for script-friendly output.
- Use `+trace` to debug DNS resolution paths.
- Use `@server` to specify a DNS server (e.g., `@1.1.1.1`).
- Combine options for custom output (e.g., `dig +short +dnssec domain.com`).

---

## DNS Tracing and Debugging

### Resolution Path Tracing
```bash
# Trace full DNS resolution from root
dig domain.com +trace

# Trace with short output
dig domain.com +trace +short

# Trace specific record type
dig domain.com MX +trace

# Debug DNS resolution issues
dig domain.com +trace +nodnssec
```

### Query Statistics and Timing
```bash
# Show query statistics
dig domain.com +stats

# Show timing information
dig domain.com +cmd

# Combine statistics and answer
dig domain.com +noall +answer +stats

# Time multiple queries
time dig domain.com +short
```

---

## Practical Reconnaissance Examples

### Basic Domain Enumeration
```bash
# Comprehensive domain analysis
dig domain.com ANY +noall +answer
dig domain.com NS +short
dig domain.com MX +short
dig domain.com TXT +short

# Find authoritative name servers
dig domain.com NS +short > nameservers.txt
```

### Subdomain Discovery Support
```bash
# Test for wildcard DNS
dig nonexistent.domain.com +short

# Check for common subdomains
for sub in www mail ftp admin api; do
    dig $sub.domain.com +short
done

# Reverse lookup on discovered IPs
for ip in $(dig domain.com +short); do
    dig -x $ip +short
done
```

### Mail Server Analysis
```bash
# Get all MX records with priorities
dig domain.com MX +noall +answer

# Resolve MX hostnames to IPs
for mx in $(dig domain.com MX +short | awk '{print $2}'); do
    echo "$mx:"
    dig $mx +short
done

# Check SPF records
dig domain.com TXT | grep -i spf
```

### Security-Focused Queries
```bash
# Check for security-related TXT records
dig domain.com TXT | grep -E "(spf|dkim|dmarc)"

# Look for CAA records (Certificate Authority Authorization)
dig domain.com CAA +short

# Check DNSSEC validation
dig domain.com +dnssec | grep -E "(RRSIG|DNSKEY)"

# Test DNS over HTTPS endpoints
dig _443._tcp.domain.com HTTPS
```

---

## Advanced Output Formatting

### Custom Output Formats
```bash
# Minimal output for scripting
dig +short +timeout=3 domain.com

# Detailed but clean format
dig domain.com +noall +answer +multiline

# JSON-like output (using external tools)
dig domain.com +short | jq -R -s 'split("\n")[:-1] | map(select(. != ""))'

# Tab-separated output for processing
dig domain.com +short | tr '\n' '\t'
```

### Batch Processing
```bash
# Process multiple domains
cat domains.txt | while read domain; do
    echo "$domain: $(dig +short $domain)"
done

# Parallel processing for speed
cat domains.txt | xargs -P 10 -I {} dig +short {}

# Save results with timestamps
echo "$(date): $(dig domain.com +short)" >> dns_history.log
```

---

## Understanding dig Output Structure

### Complete Output Breakdown
```
; <<>> DiG 9.18.1 <<>> example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;example.com.                   IN      A

;; ANSWER SECTION:
example.com.            300     IN      A       93.184.216.34

;; Query time: 45 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Sat Oct 20 10:15:30 UTC 2025
;; MSG SIZE  rcvd: 56
```

### Header Flags Explained
| Flag   | Full Name            | Meaning                            | Significance                |
| ------ | -------------------- | ---------------------------------- | --------------------------- |
| **qr** | Query Response       | This is a response (not query)     | Normal for answers          |
| **aa** | Authoritative Answer | Response from authoritative server | More reliable data          |
| **tc** | Truncated            | Response was truncated             | Use +tcp to get full answer |
| **rd** | Recursion Desired    | Client requested recursion         | Normal for most queries     |
| **ra** | Recursion Available  | Server supports recursion          | Shows server capability     |
| **ad** | Authentic Data       | DNSSEC validated response          | Security validation         |
| **cd** | Checking Disabled    | Skip DNSSEC validation             | Used for debugging          |

### Response Codes
| Code         | Meaning               | Implication                           |
| ------------ | --------------------- | ------------------------------------- |
| **NOERROR**  | Query successful      | Normal operation                      |
| **NXDOMAIN** | Domain does not exist | Domain not registered or configured   |
| **SERVFAIL** | Server failure        | DNS server error or misconfiguration  |
| **REFUSED**  | Query refused         | Server policy or security restriction |
| **FORMERR**  | Format error          | Malformed query                       |
| **NOTIMPL**  | Not implemented       | Feature not supported                 |

---

## Troubleshooting Common Issues

### DNS Resolution Problems
```bash
# Test with different DNS servers
dig @8.8.8.8 domain.com        # Google DNS
dig @1.1.1.1 domain.com        # Cloudflare DNS
dig @208.67.222.222 domain.com # OpenDNS

# Force TCP if UDP fails
dig domain.com +tcp

# Increase timeout for slow servers
dig domain.com +timeout=30

# Check if domain exists at all
dig domain.com SOA
```

### Network Connectivity Issues
```bash
# Test basic DNS connectivity
dig @8.8.8.8 google.com +short

# Check local DNS configuration
cat /etc/resolv.conf

# Test with IPv6
dig -6 @2001:4860:4860::8888 domain.com

# Use specific source address
dig -b 192.168.1.100 domain.com
```

### Performance Optimization
```bash
# Reduce query time
dig +short +timeout=3 +retry=1 domain.com

# Disable recursion for faster authoritative queries
dig @ns1.domain.com domain.com +norecurse

# Batch optimize
dig +short domain1.com domain2.com domain3.com
```

---

## Integration with Other Tools

### Combining with Standard Unix Tools
```bash
# Extract just IP addresses
dig domain.com +short | grep -E '^[0-9]+\.'

# Count DNS responses
dig domain.com +short | wc -l

# Sort and unique results
dig domain.com ANY +short | sort -u

# Filter specific record types
dig domain.com ANY +noall +answer | grep 'MX\|NS'
```

### Scripting and Automation
```bash
#!/bin/bash
# DNS reconnaissance script
domain="$1"

echo "=== DNS Analysis for $domain ==="
echo "A Records:" 
dig +short "$domain" A

echo -e "\nMX Records:"
dig +short "$domain" MX

echo -e "\nNS Records:"
dig +short "$domain" NS

echo -e "\nTXT Records:"
dig +short "$domain" TXT

# Test for zone transfer
echo -e "\nTesting Zone Transfer:"
for ns in $(dig +short "$domain" NS); do
    echo "Testing $ns:"
    dig @"$ns" "$domain" AXFR | head -5
done
```

---

## Security and Legal Considerations

### Best Practices
- **Always verify authorization** before performing DNS reconnaissance on third-party domains
- **Use appropriate delays** between queries to avoid overwhelming DNS servers
- **Respect rate limits** implemented by DNS providers
- **Document all queries** for audit trails and reporting

### Operational Security
```bash
# Use different DNS servers to avoid patterns
dig @8.8.8.8 domain.com +short
sleep 2
dig @1.1.1.1 domain.com +short

# Rotate query sources when possible
dig -b source_ip1 domain.com
dig -b source_ip2 domain.com

# Use TCP for less detectable queries
dig domain.com +tcp +short
```

### Legal Compliance
- DNS queries are generally legal as they use public infrastructure
- Zone transfer attempts may trigger security alerts
- Always ensure you have proper authorization for security assessments
- Follow responsible disclosure for security findings

---

## Quick Reference Commands

### Most Common Operations
```bash
# Basic domain lookup
dig domain.com +short

# All important records
dig domain.com ANY +noall +answer

# Mail server discovery
dig domain.com MX +short

# Name server identification
dig domain.com NS +short

# Reverse DNS lookup
dig -x IP_ADDRESS +short

# Zone transfer attempt
dig @nameserver domain.com AXFR
```

### One-Liners for Reconnaissance
```bash
# Complete domain profile
dig domain.com ANY +noall +answer | grep -E '(A|MX|NS|TXT)'

# Find all IPs for domain and subdomains
dig domain.com +short; dig www.domain.com +short; dig mail.domain.com +short

# Quick subdomain check
for sub in www mail ftp admin; do echo "$sub: $(dig $sub.domain.com +short)"; done

# Security record audit
dig domain.com TXT +short | grep -E "(spf|dkim|dmarc|_domainkey)"
```

---

## References and Additional Resources

### Official Documentation
- [BIND 9 Administrator Reference Manual](https://bind9.readthedocs.io/)
- [dig Manual Page](https://linux.die.net/man/1/dig)
- [RFC 1035 - Domain Names Implementation](https://tools.ietf.org/html/rfc1035)

### Related Tools
- **nslookup** - Older DNS lookup utility (less flexible than dig)
- **host** - Simple DNS lookup tool with clean output
- **drill** - Alternative to dig with similar functionality
- **dnsenum** - DNS enumeration tool for comprehensive discovery
- **dnsrecon** - DNS reconnaissance and enumeration script

### Online Resources
- [IANA Root Zone Database](https://www.iana.org/domains/root/db)
- [DNS Checker Online Tools](https://dnschecker.org/)
- [MXToolbox DNS Lookup](https://mxtoolbox.com/DNSLookup.aspx)

---

*Last Updated: October 20, 2025*  
*Version: 2.0 - Enhanced Dig Cheatsheet*

---

## Common Record Types

| Record | Command Example        | Description                      |
| ------ | ---------------------- | -------------------------------- |
| A      | `dig domain.com A`     | IPv4 address                     |
| AAAA   | `dig domain.com AAAA`  | IPv6 address                     |
| NS     | `dig domain.com NS`    | Authoritative name servers       |
| SOA    | `dig domain.com SOA`   | Start of Authority (zone info)   |
| MX     | `dig domain.com MX`    | Mail exchange servers            |
| TXT    | `dig domain.com TXT`   | Text records (SPF, verification) |
| CNAME  | `dig domain.com CNAME` | Canonical name / alias           |
| SRV    | `dig domain.com SRV`   | Service records                  |
| ANY    | `dig domain.com ANY`   | All records (often rate-limited) |

---

## Zone Transfer (AXFR)

```sh
dig @ns1.example.com example.com AXFR
```
> **Note:** If allowed, the server returns the full zone file. If not, you’ll see "Transfer failed" or nothing. Do not attempt against third-party domains without permission.

---

## Interpreting Output

- `;; ANSWER SECTION:` — The records returned (what you usually want)
- `;; AUTHORITY SECTION:` — Nameservers for the zone
- `;; ADDITIONAL SECTION:` — A/AAAA records for nameservers or extra data

**Header Flags:**

| Flag     | Meaning               |
| -------- | --------------------- |
| aa       | Authoritative answer  |
| ad       | DNSSEC authenticated  |
| qr       | Query response        |
| NOERROR  | Query successful      |
| NXDOMAIN | Domain does not exist |
| SERVFAIL | Server failure        |

---

## Tips

- Use `+short` for script-friendly output.
- Use `+trace` to debug DNS resolution paths.
- Use `@server` to specify a DNS server (e.g., `@1.1.1.1`).
- Combine options for custom output (e.g., `dig +short +dnssec domain.com`).