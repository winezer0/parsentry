# Vulnerability Details

This document contains detailed information about the vulnerabilities present in the example applications. This information is separated from the main documentation to prevent direct access to vulnerability solutions.

## Python Vulnerable Application

### Vulnerabilities

1. SQL Injection (`/sqli`)
   - Vulnerability: Unsanitized user input directly concatenated into SQL query
   - Example exploit: `' OR '1'='1`
   - Impact: Unauthorized data access

2. Cross-Site Scripting (`/xss`)
   - Vulnerability: Unescaped user input rendered in template
   - Example exploit: `<script>alert('XSS')</script>`
   - Impact: Client-side code execution

3. Command Injection (`/cmdi`)
   - Vulnerability: Unsanitized user input passed to system command
   - Example exploit: `localhost; ls`
   - Impact: Unauthorized command execution

### Testing Steps

#### SQL Injection
1. Visit `/sqli`
2. Input: `' OR '1'='1`
3. Result: Dumps all user records

#### XSS
1. Visit `/xss`
2. Input: `<script>alert('XSS')</script>`
3. Result: JavaScript executes in browser

#### Command Injection
1. Visit `/cmdi`
2. Input: `localhost; ls`
3. Result: Executes additional commands


### Vulnerabilities

1. SQL Injection (`/sqli`)
   - Vulnerability: Unsanitized user input directly concatenated into SQL query
   - Example exploit: `' OR '1'='1`
   - Impact: Unauthorized data access
   - Vulnerable Code: `format!("SELECT * FROM users WHERE username = '{}'", username)`

2. Command Injection (`/cmdi`)
   - Vulnerability: Unsanitized user input passed to system command
   - Example exploit: `localhost; ls`
   - Impact: Unauthorized command execution
   - Vulnerable Code: `format!("ping -c 1 {}", hostname)`

3. Path Traversal (`/file`)
   - Vulnerability: Unsanitized file path input
   - Example exploit: `../../../etc/passwd`
   - Impact: Unauthorized file access
   - Vulnerable Code: `std::fs::read_to_string(filename)`

### Testing Steps

#### SQL Injection
1. Visit `/sqli?username=admin`
2. Try exploit: `/sqli?username=' OR '1'='1`
3. Result: Dumps all user records

#### Command Injection
1. Visit `/cmdi?hostname=localhost`
2. Try exploit: `/cmdi?hostname=localhost;ls`
3. Result: Executes additional commands

#### Path Traversal
1. Visit `/file?name=README.md`
2. Try exploit: `/file?name=../../../etc/passwd`
3. Result: Reads files outside intended directory

### Safe Alternatives

1. SQL Injection Prevention:
```rust
// Use parameterized queries
conn.execute("SELECT * FROM users WHERE username = ?", [username])?;
```

2. Command Injection Prevention:
```rust
// Use Command builder with arguments
Command::new("ping")
    .arg("-c")
    .arg("1")
    .arg(hostname)
    .output()?;
```

3. Path Traversal Prevention:
```rust
// Validate and sanitize file paths
use std::path::Path;
let base_dir = Path::new("allowed_files");
let file_path = base_dir.join(filename);
if !file_path.starts_with(base_dir) {
    return Err("Path traversal detected");
}
```
