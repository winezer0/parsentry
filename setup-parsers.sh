#!/bin/bash

# Clone tree-sitter parsers if they don't exist
git clone https://github.com/tree-sitter/tree-sitter-go.git || true
git clone https://github.com/tree-sitter/tree-sitter-java.git || true
git clone https://github.com/tree-sitter/tree-sitter-javascript.git || true
git clone https://github.com/tree-sitter/tree-sitter-python.git || true
git clone https://github.com/tree-sitter/tree-sitter-rust.git || true
git clone https://github.com/tree-sitter/tree-sitter-typescript.git || true
