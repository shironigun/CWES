# How to Fuzz

## Subdomain Discovery
- Use DNS wordlists to find subdomains
- Start with common patterns (admin, dev, test, api)
- Check certificate transparency logs
- Focus on admin/dev environments

## Virtual Host Discovery
- Test Host headers for virtual hosts on same IP
- Use subdomain wordlists as vhost names
- Filter by response size differences
- Verify through multiple methods

## Parameter Discovery
- Fuzz GET parameters on discovered pages
- Test POST parameters on forms and APIs
- Look for hidden form fields
- Test file upload parameters

## Manual Verification
- Check all discovered resources manually
- Analyze response codes and content
- Look for sensitive files and admin panels
- Test parameters with different values

---

## Fuzzing directories & files

### Discovery/Web-Content/common.txt
This general-purpose wordlist contains a broad range of common directory and file names on web servers. It's an excellent starting point for fuzzing.

### Discovery/Web-Content/directory-list-2.3-medium.txt
Extensive wordlist specifically focused on directory names. It's a good choice when you need a deeper dive into potential directories.

### Discovery/Web-Content/raft-large-directories.txt
Boasts a massive collection of directory names compiled from various sources. It's a valuable resource for thorough fuzzing campaigns.

### Discovery/Web-Content/big.txt
As the name suggests, this is a massive wordlist containing both directory and file names. It's useful when you want to cast a wide net and explore all possibilities.
    


