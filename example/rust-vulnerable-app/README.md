# Rust Vulnerable Application

This is an intentionally vulnerable Rust web application for testing security analysis tools. DO NOT USE IN PRODUCTION.

## Vulnerabilities

1. SQL Injection (`/sqli`)
   - Vulnerability: Unsanitized user input directly concatenated into SQL query
   - Example exploit: `' OR '1'='1`
   - Impact: Unauthorized data access
   - Code: `format!("SELECT * FROM users WHERE username = '{}'", username)`

2. Command Injection (`/cmdi`)
   - Vulnerability: Unsanitized user input passed to system command
   - Example exploit: `localhost; ls`
   - Impact: Unauthorized command execution
   - Code: `format!("ping -c 1 {}", hostname)`

3. Path Traversal (`/file`)
   - Vulnerability: Unsanitized file path input
   - Example exploit: `../../../etc/passwd`
   - Impact: Unauthorized file access
   - Code: `std::fs::read_to_string(filename)`

## Setup

```bash
# Build the project
cargo build

# Run the application
cargo run
```

The server will start at `http://127.0.0.1:8080`

## Testing Vulnerabilities

### SQL Injection
1. Visit `/sqli?username=admin`
2. Try exploit: `/sqli?username=' OR '1'='1`
3. Result: Dumps all user records

### Command Injection
1. Visit `/cmdi?hostname=localhost`
2. Try exploit: `/cmdi?hostname=localhost;ls`
3. Result: Executes additional commands

### Path Traversal
1. Visit `/file?name=README.md`
2. Try exploit: `/file?name=../../../etc/passwd`
3. Result: Reads files outside intended directory

## Security Notice

This application contains intentional security vulnerabilities for testing purposes. DO NOT deploy in production or expose to public networks.

## Safe Alternatives

Here are the secure ways to implement these features:

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
