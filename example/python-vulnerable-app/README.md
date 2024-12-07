# Python Vulnerable Application

This is an intentionally vulnerable Flask application for testing security analysis tools. DO NOT USE IN PRODUCTION.

## Vulnerabilities

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

## Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py
```

## Testing Vulnerabilities

### SQL Injection
1. Visit `/sqli`
2. Input: `' OR '1'='1`
3. Result: Dumps all user records

### XSS
1. Visit `/xss`
2. Input: `<script>alert('XSS')</script>`
3. Result: JavaScript executes in browser

### Command Injection
1. Visit `/cmdi`
2. Input: `localhost; ls`
3. Result: Executes additional commands

## Security Notice

This application contains intentional security vulnerabilities for testing purposes. DO NOT deploy in production or expose to public networks.
