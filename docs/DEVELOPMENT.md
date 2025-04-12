## Full Setup

To resolve the issue with the openssl-sys crate, you need to install the pkg-config package and the OpenSSL development libraries. You can do this by running the following commands in your terminal:

```sh
sudo apt update
sudo apt install pkg-config libssl-dev

# Tree-sitter grammars are included in the repository and compiled during the build process.
# The following command is no longer needed:
# git submodule update --init 
```

## Building and Running (Developer Mode)

You can build and run vulnhuntrs directly using Cargo for development and testing.

### Build

```bash
cargo build --release
```

### Run

```bash
./target/release/vulnhuntrs -r <path-to-project>
```

### Example Applications

The repository includes example vulnerable applications for demonstration and testing.

#### Python app (`example/python-vulnerable-app`) + gpt-4o-0806

```bash
export OPENAI_API_KEY=your-api-key
cargo run -- -r example/python-vulnerable-app 
```

#### Rust app (`example/rust-vulnerable-app`) + gpt-4o-mini

```bash
export OPENAI_API_KEY=your-api-key
cargo run -- -r example/rust-vulnerable-app -m gpt-4o-mini
```

> These examples are for educational purposes only. Do not use them in production environments.
