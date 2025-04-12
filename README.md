<div align="center">

  <img width="250" src="./logo.png" alt="Vulnhuntrs Logo">

A tool to identify remotely exploitable vulnerabilities using LLMs and static code analysis.

**Autonomous AI-discovered 0day vulnerabilities**

</div>

Vulnhuntrs is a security analysis tool designed to detect vulnerabilities in applications. It provides static analysis capabilities to identify potential security issues in your codebase.

## Features

- Static code analysis for security vulnerabilities
- Multi-language support
- Detailed vulnerability reports
- Example vulnerable applications for testing

![analyze-python](./analyze-python.png)

### Usage

```bash
docker run --rm -v $(pwd):/work -w /work ghcr.io/HikaruEgashira/vulnhuntrs:latest -r <path-to-project>
```

## Security

This tool is intended for security research and educational purposes only. Do not use the example vulnerable applications in production environments.

## License

AGPL 3.0

## Acknowledgements

This project was inspired by [protectai/vulnhunter](https://github.com/protectai/vulnhuntr).
