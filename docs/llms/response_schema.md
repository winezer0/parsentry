# LLM Response Schema

This document defines the mandatory JSON schema that LLMs must adhere to when providing security analysis results in vulnhuntrs. The schema is enforced programmatically by parsing the LLM output against the structure defined in `src/response.rs`.

## JSON Schema Definition

The core structure is defined by the `response_json_schema()` function in `src/response.rs`. The expected top-level object must contain the following properties:

```json
{
  "type": "object",
  "properties": {
    "scratchpad": { "type": "string" },
    "analysis": { "type": "string" },
    "poc": { "type": "string" },
    "confidence_score": { "type": "integer" },
    "vulnerability_types": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"]
      }
    },
    "context_code": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "reason": { "type": "string" },
          "code_line": { "type": "string" }
        },
        "required": ["name", "reason", "code_line"]
      }
    }
  },
  "required": [
    "scratchpad",
    "analysis",
    "poc",
    "confidence_score",
    "vulnerability_types",
    "context_code"
  ]
}
```

## Field Descriptions

-   **`scratchpad`** (string, required):
    -   The LLM's internal thought process, working notes, step-by-step reasoning, or any intermediate analysis used to arrive at the final conclusion.
-   **`analysis`** (string, required):
    -   A detailed explanation of the identified security vulnerabilities, including their root cause, potential impact, and how they manifest in the code.
-   **`poc`** (string, required):
    -   A concrete Proof of Concept (PoC) or steps to exploit the identified vulnerability. This should be clear, actionable, and demonstrate the vulnerability's existence.
-   **`confidence_score`** (integer, required):
    -   A score from 0 to 100 representing the LLM's confidence in its findings. Higher scores indicate greater certainty.
-   **`vulnerability_types`** (array of strings, required):
    -   A list containing one or more strings identifying the types of vulnerabilities found. 
    -   Allowed values are strictly limited to the enum variants defined in `src/response.rs::VulnType`: `"LFI"`, `"RCE"`, `"SSRF"`, `"AFO"`, `"SQLI"`, `"XSS"`, `"IDOR"`. (Note: The `Other(String)` variant is handled internally and not expected directly from the LLM in this list).
-   **`context_code`** (array of objects, required):
    -   An array providing context for each identified vulnerability, linking it back to the source code.
    -   Each object in the array corresponds to the `ContextCode` struct in `src/response.rs` and must contain:
        -   `name` (string, required): The name of the relevant function, class, method, or code block.
        -   `reason` (string, required): An explanation of why this specific code snippet is relevant to the vulnerability.
        -   `code_line` (string, required): The specific line(s) of code identified as vulnerable or directly related.

## Importance of Adherence

Strict adherence to this schema is critical for the successful parsing and processing of the LLM's output by the vulnhuntrs application. Any deviation will likely result in parsing errors.
