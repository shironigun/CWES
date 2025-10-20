# JavaScript Deobfuscation

**Comprehensive Guide for Analyzing Obfuscated JavaScript in Penetration Testing**

## Table of Contents
- [Understanding JavaScript Obfuscation](#understanding-javascript-obfuscation)
- [Common Obfuscation Techniques](#common-obfuscation-techniques)
- [Deobfuscation Methodology](#deobfuscation-methodology)
- [Tools and Resources](#tools-and-resources)
- [Encoding Methods](#encoding-methods)
- [Practical Examples](#practical-examples)

---

## Understanding JavaScript Obfuscation

### What is Obfuscation?
**Definition:** A technique used to make code difficult to read, understand, and reverse engineer while maintaining its original functionality.

**Common Purposes:**
- **Intellectual Property Protection:** Hide proprietary algorithms
- **Anti-Tampering:** Prevent modification of client-side logic
- **Malware Evasion:** Bypass security detection systems
- **Performance:** Reduce file size (minification)

### Why Pentesters Need to Deobfuscate
- **Malware Analysis:** Understanding malicious JavaScript payloads
- **Web Application Testing:** Analyzing client-side security controls
- **Source Code Review:** Examining hidden functionality
- **Bypass Detection:** Understanding evasion techniques

---

## Common Obfuscation Techniques

### 1. Code Minification
**Purpose:** Reduce file size and readability by removing unnecessary characters.

**Characteristics:**
- Single-line code format
- Removed whitespace, comments, and line breaks
- Shortened variable names
- Files often saved with `.min.js` extension

**Example:**
```javascript
// Original
function validateUser(username, password) {
    if (username.length > 0 && password.length > 8) {
        return true;
    }
    return false;
}

// Minified
function validateUser(a,b){return a.length>0&&b.length>8}
```

### 2. Packing
**Purpose:** Advanced obfuscation using eval() with encoded payloads.

**Recognition Pattern:** Look for `function(p,a,c,k,e,d)` signature
```javascript
eval(function(p,a,c,k,e,d){
    e=function(c){return c};
    if(!''.replace(/^/,String)){
        while(c--){d[c]=k[c]||c}
        k=[function(e){return d[e]}];
        e=function(){return'\\w+'};
        c=1
    };
    while(c--){
        if(k[c]){
            p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])
        }
    }
    return p
}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

### 3. Variable Name Obfuscation
**Techniques:**
- Random character sequences: `var a1b2c3 = "data"`
- Unicode characters: `var ᵃᵇᶜ = "hidden"`
- Misleading names: `var jQuery = maliciousFunction`

### 4. String Obfuscation
**Methods:**
- String splitting: `"hel" + "lo" + "world"`
- Character codes: `String.fromCharCode(72,101,108,108,111)`
- Encoding: Base64, Hex, ROT13

### 5. Control Flow Obfuscation
**Techniques:**
- Dead code injection
- Unnecessary loops and conditions
- Function call indirection
- Switch statement scrambling


---

## Deobfuscation Methodology

### Step 1: Initial Analysis
```bash
# Check file type and basic information
file suspicious.js
strings suspicious.js | head -20

# Look for common obfuscation patterns
grep -E "(eval|unescape|fromCharCode|String\.prototype)" suspicious.js
```

### Step 2: Identify Obfuscation Type
**Visual Inspection Checklist:**
- [ ] Single line code (minification)
- [ ] `eval(function(p,a,c,k,e,d)` pattern (packing)
- [ ] Excessive escape characters
- [ ] Base64/Hex patterns
- [ ] Unicode characters
- [ ] String concatenation patterns

### Step 3: Apply Appropriate Deobfuscation
**Manual Techniques:**
```javascript
// For packed code - extract and decode the payload
// Replace eval() with console.log() to see unpacked code

// For string concatenation - use browser console
var obfuscated = "hel" + "lo" + " wor" + "ld";
console.log(obfuscated);

// For character codes
var decoded = String.fromCharCode(72,101,108,108,111);
console.log(decoded); // "Hello"
```

### Step 4: Static Analysis
- **Variable Tracking:** Map obfuscated variable names to functionality
- **Function Analysis:** Understand what each function does
- **Data Flow:** Track how data moves through the code
- **External Calls:** Identify network requests, DOM manipulation

### Step 5: Dynamic Analysis
```javascript
// Add logging to understand execution flow
console.log("Function called with:", arguments);

// Hook important functions
var originalEval = eval;
eval = function(code) {
    console.log("Eval called with:", code);
    return originalEval(code);
};
```

---

## Tools and Resources

### Online Deobfuscation Tools
| Tool                  | Purpose                   | URL                                                       |
| --------------------- | ------------------------- | --------------------------------------------------------- |
| **JSNice**            | Statistical deobfuscation | http://jsnice.org/                                        |
| **JSBeautifier**      | Code formatting           | https://beautifier.io/                                    |
| **UnPacker**          | Packed code extraction    | https://matthewfl.com/unPacker.html                       |
| **JSFuck Decoder**    | JSFuck deobfuscation      | https://enkhee-osiris.github.io/Deobfuscation/            |
| **Cipher Identifier** | Encoding detection        | https://www.boxentriq.com/code-breaking/cipher-identifier |

### Browser-Based Tools
```javascript
// Browser console techniques
// 1. Pretty print minified code
JSON.stringify(eval(obfuscatedCode), null, 2)

// 2. Hook eval calls
(function() {
    var _eval = eval;
    eval = function(x) {
        console.log('eval:', x);
        return _eval(x);
    };
})();

// 3. Intercept function calls
Function.prototype.call = new Proxy(Function.prototype.call, {
    apply: function(target, thisArg, argumentsList) {
        console.log('Function called:', thisArg, argumentsList);
        return target.apply(thisArg, argumentsList);
    }
});
```

### Command Line Tools
```bash
# Node.js for JavaScript execution
node -e "console.log(require('util').inspect(yourObfuscatedCode))"

# Python for string manipulation
python3 -c "import base64; print(base64.b64decode('encoded_string').decode())"

# Grep patterns for analysis
grep -oE "'[^']*'" file.js | sort | uniq  # Extract all strings
grep -oE "\b[a-zA-Z_$][a-zA-Z0-9_$]*\b" file.js | sort | uniq  # Extract identifiers
```

### Obfuscation Tools (For Understanding)
| Tool                    | Type                 | URL                                   |
| ----------------------- | -------------------- | ------------------------------------- |
| **JavaScript Minifier** | Minification         | https://javascript-minifier.com/      |
| **Obfuscator.io**       | Advanced obfuscation | https://obfuscator.io/                |
| **JSFuck**              | Esoteric encoding    | http://www.jsfuck.com/                |
| **JJEncode**            | Japanese encoding    | https://utf-8.jp/public/jjencode.html |
| **AAEncode**            | ASCII Art encoding   | https://utf-8.jp/public/aaencode.html |


---

## Encoding Methods

### Base64 Encoding
**Characteristics:**
- Uses only alphanumeric characters plus `+` and `/`
- Length is always a multiple of 4
- Padding with `=` characters when needed
- Can encode binary data

**Detection:**
```bash
# Pattern recognition
echo "dGVzdCBzdHJpbmc=" | grep -E '^[A-Za-z0-9+/]*={0,2}$'
```

**Decoding:**
```bash
# Command line
echo "SGVsbG8gV29ybGQ=" | base64 -d
# Output: Hello World

# JavaScript
atob("SGVsbG8gV29ybGQ=")  // "Hello World"
btoa("Hello World")       // "SGVsbG8gV29ybGQ="

# Python
import base64
base64.b64decode("SGVsbG8gV29ybGQ=").decode()
```

### Hexadecimal Encoding
**Characteristics:**
- Uses only characters 0-9 and a-f (case insensitive)
- Each byte represented by 2 hex characters
- No padding required

**Detection and Decoding:**
```bash
# Command line encoding
echo "Hello World" | xxd -p
# Output: 48656c6c6f20576f726c640a

# Command line decoding
echo "48656c6c6f20576f726c64" | xxd -p -r
# Output: Hello World

# JavaScript
// Hex to string
function hexToString(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

// String to hex
function stringToHex(str) {
    var hex = '';
    for (var i = 0; i < str.length; i++) {
        hex += str.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
}
```

### ROT13/Caesar Cipher
**Characteristics:**
- Shifts each letter by a fixed number of positions
- ROT13 shifts by 13 positions (self-inverse)
- Only affects alphabetic characters

**Decoding:**
```bash
# ROT13 encode/decode (same operation)
echo "Hello World" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: Uryyb Jbeyq

# Generic Caesar cipher (shift by N)
# Shift by 3 (Caesar cipher)
echo "HELLO" | tr 'A-Z' 'D-ZA-C'

# JavaScript ROT13
function rot13(str) {
    return str.replace(/[A-Za-z]/g, function(char) {
        var start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + 13) % 26) + start);
    });
}
```

### URL Encoding
**Characteristics:**
- Replaces unsafe characters with `%` followed by hex values
- Common in web applications

**Decoding:**
```javascript
// JavaScript
decodeURIComponent("%48%65%6C%6C%6F%20%57%6F%72%6C%64")  // "Hello World"
encodeURIComponent("Hello World")  // "Hello%20World"

# Python
import urllib.parse
urllib.parse.unquote("%48%65%6C%6C%6F%20%57%6F%72%6C%64")
```

### Unicode Escape Sequences
**Common Forms:**
- `\uXXXX` - 4-digit Unicode
- `\u{XXXXX}` - Variable length Unicode
- `\xXX` - 2-digit hex

**Decoding:**
```javascript
// JavaScript automatically handles these
"\u0048\u0065\u006C\u006C\u006F"  // "Hello"
"\x48\x65\x6C\x6C\x6F"           // "Hello"

// Manual decoding
function unicodeDecode(str) {
    return str.replace(/\\u[\dA-Fa-f]{4}/g, function(match) {
        return String.fromCharCode(parseInt(match.replace('\\u', ''), 16));
    });
}
```

---

## Practical Examples

### Example 1: Packed JavaScript
**Obfuscated Code:**
```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

**Deobfuscation Steps:**
1. Replace `eval(` with `console.log(`
2. Execute in browser console
3. Result: `console.log('HTB JavaScript Deobfuscation Module');`

### Example 2: String Concatenation
**Obfuscated:**
```javascript
var _0x1234 = ['pass', 'word', 'admin'];
var login = _0x1234[2] + _0x1234[0] + _0x1234[1];
```

**Deobfuscation:**
```javascript
// Trace variable values
console.log(_0x1234);     // ['pass', 'word', 'admin']
console.log(login);       // 'adminpassword'
```

### Example 3: Character Code Obfuscation
**Obfuscated:**
```javascript
String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41)
```

**Deobfuscation:**
```javascript
// Execute in console or convert manually
// Result: alert('XSS')
```

### Example 4: JSFuck
**Obfuscated:**
```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```

**Deobfuscation:**
- Use JSFuck decoder online tool
- Result: Typically `alert(1)` or similar

---

## Advanced Techniques

### Anti-Debugging Measures
```javascript
// Detect developer tools
setInterval(function() {
    if (window.outerHeight - window.innerHeight > 200) {
        // Developer tools detected
        debugger;
    }
}, 1000);

// Function length check
if (arguments.callee.toString().length > 100) {
    // Code has been tampered with
}
```

### Dynamic String Construction
```javascript
// Obfuscated API endpoint
var endpoint = atob("aHR0cDovL2V2aWwuY29t") + "/api/" + 
               String.fromCharCode(117,115,101,114,115);
// Deobfuscated: http://evil.com/api/users
```

### Environment Detection
```javascript
// Check if running in browser vs Node.js
var isNode = (typeof module !== 'undefined' && module.exports);
if (isNode) {
    // Server-side payload
} else {
    // Client-side payload
}
```

---

## Best Practices for Pentesters

### 1. Safety First
- **Never execute unknown code directly**
- **Use isolated environments** (VMs, containers)
- **Static analysis before dynamic analysis**

### 2. Documentation
- **Keep detailed notes** of deobfuscation steps
- **Screenshot important findings**
- **Save original and deobfuscated versions**

### 3. Automation
```bash
# Create a deobfuscation toolkit script
#!/bin/bash
echo "=== JavaScript Deobfuscation Toolkit ==="
echo "1. Checking for common patterns..."
grep -E "(eval|unescape|fromCharCode)" "$1"

echo "2. Extracting strings..."
grep -oE "'[^']*'" "$1" | head -10

echo "3. Base64 patterns..."
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' "$1" | head -5
```

### 4. Reporting
- **Include original obfuscated code**
- **Show deobfuscation methodology**
- **Explain security implications**
- **Provide mitigation recommendations**

---

## Common Pitfalls

### ⚠️ Important Notes
- **Empty lines at the start** can change obfuscation output
- **Browser differences** in JavaScript execution
- **Time-based anti-analysis** measures
- **Multiple layers** of obfuscation
- **Context-dependent** code execution

### Troubleshooting
```javascript
// If eval replacement doesn't work, try:
var originalEval = window.eval;
window.eval = function(code) {
    console.log("Intercepted eval:", code);
    return originalEval.call(this, code);
};

// For function constructors:
var originalFunction = Function;
Function = function() {
    console.log("Function constructor called:", arguments);
    return originalFunction.apply(this, arguments);
};
```






