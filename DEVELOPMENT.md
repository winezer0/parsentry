# Development Guide

This document provides guidelines for developing Vulnhuntrs.

## Development Environment Setup

1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Install development dependencies
```bash
cargo install cargo-watch
cargo install cargo-audit
```

## Project Structure

```
.
├── src/                    # Source code
│   ├── analyzer.rs         # Core analysis logic
│   └── main.rs            # Entry point
├── example/               # Example vulnerable applications
│   ├── python-vulnerable-app/
│   └── rust-vulnerable-app/
└── tests/                 # Test files
```

## Development Workflow

1. Create a new branch for your feature
```bash
git checkout -b feature/your-feature-name
```

2. Run tests during development
```bash
cargo watch -x test
```

3. Run security audit
```bash
cargo audit
```

4. Run formatter and linter
```bash
cargo fmt
cargo clippy
```

## Testing

- Write unit tests for new functionality
- Include integration tests for analyzer features
- Test against example vulnerable applications

## Creating Example Vulnerable Applications

When creating example applications:

1. Document each vulnerability
2. Include clear comments explaining the security issues
3. Add test cases demonstrating the vulnerabilities
4. Provide fix examples in documentation

## Pull Request Guidelines

1. Ensure all tests pass
2. Update documentation
3. Add test cases
4. Follow Rust coding standards
5. Include vulnerability detection rules if applicable

## Security Considerations

- Do not include actual exploits
- Mark vulnerable examples clearly
- Use safe coding practices in the main tool
- Document security implications
