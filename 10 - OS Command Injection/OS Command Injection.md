Injection types in web applications depends on the type of web query being executed.

Injection 	                               Description
OS Command Injection 	                   Occurs when user input is directly used as part of an OS command.
Code Injection 	Occurs                     when user input is directly within a function that evaluates code.
SQL Injections 	Occurs                     when user input is directly used as part of an SQL query.
Cross-Site Scripting/HTML Injection    	   Occurs when exact user input is displayed on a web page.
LDAP Injection                               Occurs when user input is directly used as part of an LDAP query.
NoSQL Injection                             Occurs when user input is directly used as part of a NoSQL query.
Header Injection                             Occurs when user input is directly used within HTTP headers.
XPath Injection                             Occurs when user input is directly used as part of an XPath query.
IMAP/SMTP Injection                          Occurs when user input is directly used as part of an IMAP/SMTP query.
ORM Injection                              Occurs when user input is directly used as part of an ORM query.


## OS Command Injection

OS Command Injection occurs when user input is directly used as part of an OS command. This can allow an attacker to execute arbitrary commands on the host operating system via a vulnerable application.

## Detection

Injection Operator 	Injection Character 	URL-Encoded Character 	Executed Command
Semicolon 	; 	%3b 	Both (not work in windows if used in CMD. works in PowerShell)
New Line 	\n 	%0a 	Both
Background 	& 	%26 	Both (second output generally shown first)
Pipe 	| 	%7c 	Both (only second output is shown)
AND 	&& 	%26%26 	Both (only if first succeeds)
OR 	|| 	%7c%7c 	Second (only if first fails)
Sub-Shell 	`` 	%60%60 	Both (Linux-only)
Sub-Shell 	$() 	%24%28%29 	Both (Linux-only)


## Common Operators by Injection Type

Injection Type 	Operators
SQL Injection 	' , ; -- /* */
Command Injection 	; &&
LDAP Injection 	* ( ) & |
XPath Injection 	' or and not substring concat count
OS Command Injection 	; & |
Code Injection 	' ; -- /* */ $() ${} #{} %{} ^
Directory Traversal/File Path Traversal 	../ ..\\ %00
Object Injection 	; & |
XQuery Injection 	' ; -- /* */
Shellcode Injection 	\x \u %u %n
Header Injection 	\n \r\n \t %0d %0a %09

### Filter/WAF Detection
- Use tools like Burp Suite, OWASP ZAP, or Wfuzz to send various payloads.
- Analyze responses for error messages, status codes, or blocked requests.
- Check for common WAF signatures using tools like WAFW00F.
- send payloads as one character at a time to identify filtering mechanisms as even spaces can be filtered out.

## Identify blocked characters

step 1:

- Identify the input fields and parameters that may be vulnerable to OS command injection.

step 2:

- use one character at a time to identify blocked characters.

step 3:

- Test common special characters.

```bash
# Test common special characters
; & | ` $ ( ) < > ' " \n \r \t %0d %0a %09
``` 

step 4:

- Observe responses for:

- Changes in HTTP status codes (e.g., 403 Forbidden)
- Error messages indicating blocked characters
- Differences in page content or behavior
- Increased latency or timeouts
- Redirections to error pages

## Bypass Techniques

### Bypass frontend validation

- Use a proxy tool to intercept and modify requests.
- Remove or alter client-side validation scripts.

### Bypass space filters

- Use alternative encodings for spaces:
  - URL encoding: `%20`
  - Tab character: `%09`
  - Newline character: `%0a`
  - Carriage return: `%0d`
  - $IFS variable (Linux): `${IFS}` - represents space, tab, and newline.
  - Bash Brace Expansion (Linux): `{ls,-la}` - can be used to create spaces.

### using environment variables 

- use printenv command to list environment variables and identify useful ones having special characters.
- use echo command to print the value of specific environment variables.
- Extract needed special characters from environment variables.
- Leverage environment variables to construct payloads that bypass filters.

#### Extract special characters from environment variables in Linux

- use printenv command to list environment variables.
- use echo command to print the value of specific environment variables.
- Extract needed special characters from environment variables using substring syntax.
  - Syntax: `${VARIABLE:position:length}`

**Examples:**
-  `$IFS` in Linux can be used to represent space, tab, and newline.

- Extract special characters from environment variables.
  - Example: `${PATH:0:1}` to extract the slash (`/`) as the first character of the PATH variable.
  - Example: `${LS_COLORS:10:1}` to extract the semicolon (`;`) as the 11th character of the LS_COLORS variable.

#### Extract special characters from environment variables in Windows

**For CMD:**
- use set command to list environment variables.
- use echo command to print the value of specific environment variables.
- Extract needed special characters from environment variables using substring syntax.
  - `%VARIABLE:~start,length%`
- Leverage environment variables to construct payloads that bypass filters.
- Examples:

**For PowerShell:**
- In PowerShell a word is considered as an array of characters, so you can access individual characters using array indexing.
- `env:VARIABLE[index]`

Or

- use Get-ChildItem Env: to list environment variables.
- use echo command to print the value of specific environment variables.
- Extract needed special  from environment variables using substring syntax.
  - `$env:VARIABLE.substring(start,length)`
- Leverage environment variables to construct payloads that bypass filters.
- 
**- Examples:**

- Extract special characters from environment variables.
  - Example: `$env:PATH.substring(0,1)` to extract the backslash (`\`) as the first character of the PATH variable.

### Character Shifting

- Shift ASCII values of blocked characters to bypass filters.
- 