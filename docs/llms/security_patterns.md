# Security Patterns

This document outlines the regular expression patterns used in `src/security_patterns.rs` to identify potentially security-relevant code sections across different languages. These patterns help focus the analysis but are not exhaustive and serve as initial indicators rather than definitive proof of vulnerabilities.

## Purpose

The `SecurityRiskPatterns` struct holds a collection of regex patterns designed to match common constructs associated with potential security risks, such as:
- Web request handlers
- Database interactions
- File system operations
- Command execution
- Network API calls

## Defined Patterns (Examples from `src/security_patterns.rs`)

*Note: This is a representative sample, not the complete list.*

### Python
- `async\sdef\s\w+\(.*?request`: Matches asynchronous function definitions likely handling web requests.
- `@app\.route\(.*?\)`: Matches Flask route decorators.
- `gr.Interface\(.*?\)`: Matches Gradio interface initializations.

### JavaScript/TypeScript
- `app\.(get|post|put|delete)\(.*?\)`: Matches Express.js route definitions.
- `fetch\(.*?\)`: Matches calls to the Fetch API.
- `axios\.(get|post|put|delete)`: Matches calls using the Axios HTTP client.

### Rust
- `async\s+fn\s+\w+.*?Request`: Matches asynchronous functions potentially handling web requests.
- `#\[.*?route.*?\]`: Matches generic route attributes.
- `#\[(get|post|put|delete)\(.*?\)]`: Matches Actix-web specific route attributes.
- `HttpServer::new`: Matches Actix-web server initialization.

### Generic (Potentially applicable across languages)
- `exec\(`, `system\(`, `subprocess\.`, `Command::new`: Patterns related to command execution.
- `SELECT.*?FROM`, `INSERT INTO`, `UPDATE.*?SET`, `DELETE FROM`: Basic SQL query patterns.
- `open\(`, `read\(`, `write\(`, `fs::`: File system operation patterns.
- `dangerouslySetInnerHTML`, `eval\(`: Patterns often associated with XSS or code injection risks.

## Usage

These patterns are likely used by the `parser` module (`src/parser.rs`) or the `analyzer` (`src/analyzer.rs`) to:
1.  Identify potentially sensitive code regions within a file.
2.  Extract relevant code snippets (`ContextCode`) to be included in the LLM response.
3.  Potentially guide the LLM's attention towards these areas during analysis.

## Limitations

- **Not Exhaustive**: These patterns do not cover all possible security risks or framework-specific APIs.
- **Potential False Positives/Negatives**: Regex matching is inherently limited and may flag benign code or miss complex vulnerabilities.
- **Context is Key**: The patterns identify *potential* areas of interest; actual vulnerability depends on the full context and data flow, which requires deeper analysis (often by the LLM).
