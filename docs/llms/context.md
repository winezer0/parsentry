# Context Provisioning for LLMs

This document describes how context is gathered and provided to the LLM during the security analysis process in vulnhuntrs.

## 1. Project-Level Context

- **README Summary**: Before analyzing individual files, the project's root `README.md` is read and summarized using a dedicated LLM prompt (`README_SUMMARY_PROMPT_TEMPLATE` in `src/prompts/analysis.rs`). This summary provides the LLM with an overview of the project's purpose, functionality, and potentially relevant technical details.
- **File List**: The list of all files within the project (or a specified subdirectory) is passed to the analysis function (`analyze_file` in `src/analyzer.rs`). This helps the LLM understand the scope of the analysis and potentially infer relationships between files.

## 2. File-Level Context

- **Full Source Code**: The complete source code of the file currently being analyzed is provided directly within the main analysis prompt (`INITIAL_ANALYSIS_PROMPT_TEMPLATE` or vulnerability-specific prompts).
- **File Path**: The relative path of the file being analyzed is included in the context to help the LLM understand its location within the project structure.
- **Language**: While not explicitly passed as separate metadata in the current implementation, the language is implicitly understood by the LLM based on the file extension and code content. The parser used (`src/parser.rs`) is language-specific.

## 3. Context Integration in Prompts

The gathered context is integrated into the prompts sent to the LLM:

- The **README summary** is typically included in the initial analysis prompt to give the LLM a high-level understanding before diving into the code.
- The **file path** and **source code** are the primary inputs for the detailed analysis prompts.
- The **list of all project files** might be used implicitly by the LLM or in future extensions to understand imports and dependencies better.
