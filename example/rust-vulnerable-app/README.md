# Rust Vulnerable Application

This is an intentionally vulnerable Rust web application for testing security analysis tools. DO NOT USE IN PRODUCTION.

## Overview

This application contains intentional security vulnerabilities for testing the vulnhuntrs tool. The specific vulnerabilities and their details can be found in the root `answer.md` file.

The application implements several endpoints that demonstrate common web application security issues:

- `/sqli` - SQL query endpoint
- `/cmdi` - System command endpoint
- `/file` - File access endpoint

## Setup

```bash
# Build the project
cargo build

# Run the application
cargo run
```

The server will start at `http://127.0.0.1:8080`

## Security Notice

This application contains intentional security vulnerabilities for testing purposes. DO NOT deploy in production or expose to public networks.