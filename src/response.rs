use serde::{Deserialize, Serialize};

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
