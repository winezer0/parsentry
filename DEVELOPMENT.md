## Full Setup

To resolve the issue with the openssl-sys crate, you need to install the pkg-config package and the OpenSSL development libraries. You can do this by running the following commands in your terminal:

```sh
sudo apt update
sudo apt install pkg-config libssl-dev

# INSTALL tree-sitter-lang
git submodule update --init
```
