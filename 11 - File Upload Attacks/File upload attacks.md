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

### Upload Exploits

- Once the vulnerability is identified, upload various exploits based on the backend language of the web application.
- Use publicly available web shells or the ones from `seclists`.
- For example, for php, `phpbash` is the popular web shell.

## shells

- Web shells or reverse shells can be used to gain remote access to the server
- These shells can be uploaded as files and can interact with the backend server by executing shell commands and returns the output the output on the web interface.
- A web shell has to be written in the same language used by the web application's backend (e.g., PHP, ASP, JSP, etc.)


### Web Shell vs Reverse Shell

- A web shell works when a port on the server is open to accept incoming connections (usually port 80 or 443 for HTTP/HTTPS) to connect with the web server's terminal.
![Web Shell](./images/Web%20Shell.png)

- A reverse shell works when the server is behind a firewall or NAT and cannot accept incoming connections. In this case, the server initiates an outbound connection to the attacker's machine, which is listening for incoming connections.
![Reverse Shell](./images/Reverse%20Shell.png)