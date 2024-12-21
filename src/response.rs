use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum VulnType {
    LFI,
    RCE,
    SSRF,
    AFO,
    SQLI,
    XSS,
    IDOR,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextCode {
    pub name: String,
    pub reason: String,
    pub code_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub scratchpad: String,
    pub analysis: String,
    pub poc: String,
    pub confidence_score: i32,
    pub vulnerability_types: Vec<VulnType>,
    pub context_code: Vec<ContextCode>,
}

pub fn response_json_schema() -> serde_json::Value {
    json!({
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
        "required": ["scratchpad", "analysis", "poc", "confidence_score", "vulnerability_types", "context_code"]
    })
}

impl Response {
    pub fn print_readable(&self) {
        println!("\n📝 Analysis Report");
        println!("{}", "=".repeat(80));

        println!("\n🔍 Analysis:");
        println!("{}", "-".repeat(80));
        println!("{}", self.analysis);

        if !self.vulnerability_types.is_empty() {
            println!("\n⚠️  Identified Vulnerabilities:");
            println!("{}", "-".repeat(80));
            for vuln in &self.vulnerability_types {
                println!("  • {:?}", vuln);
            }
        }

        println!("\n🎯 Confidence Score: {}%", self.confidence_score);
        println!("{}", "-".repeat(80));

        if !self.poc.is_empty() {
            println!("\n🔨 Proof of Concept:");
            println!("{}", "-".repeat(80));
            println!("{}", self.poc);
        }

        if !self.context_code.is_empty() {
            println!("\n📄 Relevant Code Context:");
            println!("{}", "-".repeat(80));
            for context in &self.context_code {
                println!("Function: {}", context.name);
                println!("Reason: {}", context.reason);
                println!("Code: {}", context.code_line);
                println!();
            }
        }

        if !self.scratchpad.is_empty() {
            println!("\n📓 Analysis Notes:");
            println!("{}", "-".repeat(80));
            println!("{}", self.scratchpad);
        }

        println!(); // Add final newline for better spacing
    }
}
