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
    pub path: String,
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

/// Response構造体のJSONスキーマを返す。
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
                        "code_line": { "type": "string" },
                        "path": { "type": "string" }
                    },
                    "required": ["name", "reason", "code_line", "path"]
                }
            }
        },
        "required": ["scratchpad", "analysis", "poc", "confidence_score", "vulnerability_types", "context_code"]
    })
}

impl Response {
    /// 人間が読みやすい解析レポートを出力する。
    pub fn print_readable(&self) {
        println!("\n📝 解析レポート");
        println!("{}", "=".repeat(80));

        println!("\n🔍 解析結果:");
        println!("{}", "-".repeat(80));
        println!("{}", self.analysis);

        if !self.poc.is_empty() {
            println!("\n🔨 PoC（概念実証コード）:");
            println!("{}", "-".repeat(80));
            println!("{}", self.poc);
        }

        if !self.context_code.is_empty() {
            println!("\n📄 関連コードコンテキスト:");
            println!("{}", "-".repeat(80));
            for context in &self.context_code {
                println!("関数名: {}", context.name);
                println!("理由: {}", context.reason);
                println!("コード: {}", context.code_line);
                println!("パス: {}", context.path);
                println!();
            }
        }

        if !self.scratchpad.is_empty() {
            println!("\n📓 解析ノート:");
            println!("{}", "-".repeat(80));
            println!("{}", self.scratchpad);
        }

        println!();
    }

    /// 解析レポートをMarkdown形式で返す
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# 解析レポート\n\n");

        md.push_str("## 解析結果\n\n");
        md.push_str(&self.analysis);
        md.push_str("\n\n");

        if !self.poc.is_empty() {
            md.push_str("## PoC（概念実証コード）\n\n");
            md.push_str("```text\n");
            md.push_str(&self.poc);
            md.push_str("\n```\n\n");
        }

        if !self.context_code.is_empty() {
            md.push_str("## 関連コードコンテキスト\n\n");
            for context in &self.context_code {
                md.push_str(&format!("### 関数名: {}\n", context.name));
                md.push_str(&format!("- 理由: {}\n", context.reason));
                md.push_str(&format!("- パス: {}\n", context.path));
                md.push_str("```rust\n");
                md.push_str(&context.code_line);
                md.push_str("\n```\n\n");
            }
        }

        if !self.scratchpad.is_empty() {
            md.push_str("## 解析ノート\n\n");
            md.push_str(&self.scratchpad);
            md.push_str("\n\n");
        }

        md
    }
}
