# LLM Analysis Flow

This document describes the end-to-end process vulnhuntrs follows when analyzing a file using Large Language Models (LLMs).

The core logic resides primarily within the `analyze_file` function in `src/analyzer.rs`.

## Steps

1.  **Initialization**:
    *   An API client for the selected LLM service (e.g., OpenAI, Gemini) is created (`create_api_client`).
    *   Project-level context (README summary) might be pre-generated if analyzing multiple files.

2.  **Read Target File**: The content of the file specified for analysis is read into memory.

3.  **Prepare Initial Analysis Prompt**:
    *   The `INITIAL_ANALYSIS_PROMPT_TEMPLATE` is combined with the `SYS_PROMPT_TEMPLATE`, analysis guidelines, the file's source code, and potentially the README summary.
    *   The prompt explicitly requests the output in the predefined JSON schema.

4.  **Execute Initial LLM Request**:
    *   A `ChatRequest` is constructed with the prepared prompt.
    *   The request is sent to the LLM API via `execute_chat_request`.
    *   The LLM's response (expected to be a JSON string) is received.

5.  **Parse Initial Response**:
    *   The received JSON string is parsed into the `Response` struct defined in `src/response.rs` using `parse_json_response`.
    *   This involves validating the structure against `response_json_schema()`.

6.  **(Optional) Vulnerability-Specific Deep Dive (Iterative)**:
    *   *Based on the current implementation structure (presence of `vuln_specific` prompts), this step is implied or intended for future enhancement, although the exact trigger mechanism isn't fully detailed in `analyzer.rs` alone.*
    *   If the initial analysis identifies potential vulnerabilities (e.g., based on `vulnerability_types` in the response), the system *could* iterate:
        *   Select a specific vulnerability type (e.g., SQLI).
        *   Retrieve the corresponding prompt and bypass techniques from `vuln_specific::get_vuln_specific_info()`.
        *   Prepare a new prompt combining the specific instructions, relevant code context (potentially from the initial `context_code`), and bypass info.
        *   Execute another LLM request.
        *   Parse the response and potentially refine the initial `Response` object (e.g., update `analysis`, `poc`, `confidence_score`).
        *   Repeat for other identified vulnerability types.

7.  **Final Result**: The (potentially refined) `Response` object, containing the aggregated findings, is returned by the `analyze_file` function.

## Key Components Involved

-   `src/analyzer.rs`: Orchestrates the overall flow.
-   `src/prompts/`: Contains all prompt templates.
-   `src/response.rs`: Defines the `Response` struct and the JSON schema.
-   `src/parser.rs`: Handles code parsing (likely used for extracting `context_code`, though details depend on implementation).
-   `genai` crate: Used for interacting with the LLM API.
-   `serde_json`: Used for JSON parsing and schema definition.
