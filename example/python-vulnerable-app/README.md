# Python Vulnerable Application

This is an intentionally vulnerable Flask application for testing security analysis tools. DO NOT USE IN PRODUCTION.

## Overview

This application contains intentional security vulnerabilities for testing the vulnhuntrs tool. The specific vulnerabilities and their details can be found in the root `answer.md` file.

The application implements several endpoints that demonstrate common web application security issues:

- `/sqli` - SQL query endpoint
- `/xss` - Template rendering endpoint
- `/cmdi` - System command endpoint

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

## Security Notice

This application contains intentional security vulnerabilities for testing purposes. DO NOT deploy in production or expose to public networks.