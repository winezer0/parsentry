## Full Setup

To resolve the issue with the openssl-sys crate, you need to install the pkg-config package and the OpenSSL development libraries. You can do this by running the following commands in your terminal:

```sh
sudo apt update
sudo apt install pkg-config libssl-dev

# Tree-sitter grammars are included in the repository and compiled during the build process.
# The following command is no longer needed:
# git submodule update --init 
```
