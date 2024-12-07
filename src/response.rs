use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnType {
    LFI,
    RCE,
    SSRF,
    AFO,
    SQLI,
    XSS,
    IDOR,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContextCode {
    pub name: String,
    pub reason: String,
    pub code_line: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub scratchpad: String,
    pub analysis: String,
    pub poc: String,
    pub confidence_score: i32,
    pub vulnerability_types: Vec<VulnType>,
    pub context_code: Vec<ContextCode>,
}

impl Response {
    pub fn print_readable(&self) {
        println!("Analysis:");
        println!("{}", "-".repeat(40));
        println!("Scratchpad:\n{}", self.scratchpad);
        println!("{}", "-".repeat(40));
        println!("Analysis:\n{}", self.analysis);
        println!("{}", "-".repeat(40));
        println!("PoC:\n{}", self.poc);
        println!("{}", "-".repeat(40));
        println!("Confidence Score: {}", self.confidence_score);
        println!("{}", "-".repeat(40));
        println!("Vulnerability Types:");
        for vuln_type in &self.vulnerability_types {
            println!("  - {:?}", vuln_type);
        }
        println!("{}", "-".repeat(40));
        println!("Context Code:");
        for context in &self.context_code {
            println!("  Name: {}", context.name);
            println!("  Reason: {}", context.reason);
            println!("  Code Line: {}", context.code_line);
            println!();
        }
    }
}
