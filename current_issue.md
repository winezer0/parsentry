# Refactor: Replace stack-graphs with tree-sitter queries for code analysis

## Background

Currently, `vulnhuntrs` relies on the `stack-graphs` library and associated `tree-sitter-stack-graphs-*` crates for code analysis tasks like finding definitions. To simplify dependencies and gain more direct control over the analysis logic, we will replace the `stack-graphs` dependency with direct usage of `tree-sitter` queries.

This involves removing the `stack-graphs` related crates and refactoring the `src/parser.rs` module to use `tree-sitter`'s query API for finding definitions and references.

## Tasks

-   [x] Remove `stack-graphs` related dependencies from `Cargo.toml`:
    -   `stack-graphs`
    -   `tree-sitter-stack-graphs`
    -   `tree-sitter-stack-graphs-java`
    -   `tree-sitter-stack-graphs-javascript`
    -   `tree-sitter-stack-graphs-python`
    -   `tree-sitter-stack-graphs-typescript`
-   [x] Refactor `src/parser.rs`:
    -   [x] Remove `use` declarations for `stack_graphs` and `tree-sitter-stack-graphs`.
    -   [x] Replace `StackGraphsError` with a standard error type (e.g., `anyhow::Error`).
    -   [x] Remove the `get_language_configurations` and `index_files` functions.
    -   [x] Modify the `CodeParser` struct:
        -   [x] Remove `graph`, `db_writer`, and `*_config` fields.
        -   [x] Add a `tree_sitter::Parser` field and logic to load `tree_sitter::Language` as needed.
        -   [x] Update the `new` method to initialize the parser.
        -   [x] Update the `add_file` method to remove stack graph logic.
    -   [x] Reimplement `find_definition` using `tree-sitter` queries.
        -   [x] Create/verify `definitions.scm` query files for supported languages (Python, Java, JS, TS) in their respective `tree-sitter-*/queries/` directories.
    -   [x] Reimplement `find_references` using `tree-sitter` queries.
        -   [x] Create/verify `references.scm` query files for supported languages in their respective `tree-sitter-*/queries/` directories.
    -   [x] Update tests in `src/parser.rs` to reflect the changes and test the new query-based implementation.
-   [x] Update `src/analyzer.rs`:
    -   [x] Adjust calls to `CodeParser::new()`.
    -   [x] Adjust calls to `parser.add_file()`.
    -   [x] Adjust calls to `parser.find_definition()` to match the new signature and return type.
-   [x] Ensure the project builds successfully (`cargo build`).
-   [x] Ensure all tests pass (`cargo test`).
-   [x] Update documentation (`README.md`, `docs/DEVELOPMENT.md`, potentially remove `docs/stack-graphs/`) to reflect the removal of `stack-graphs` and the use of `tree-sitter` queries.

## Affected Files

-   `Cargo.toml`
-   `src/parser.rs`
-   `src/analyzer.rs`
-   Potentially test files and documentation files.
-   `tree-sitter-*/queries/definitions.scm` (New or existing)
-   `tree-sitter-*/queries/references.scm` (New or existing)
