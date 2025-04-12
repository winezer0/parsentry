use anyhow::{Error, Result};
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, JsonSpec};
use genai::{Client, ClientConfig};
use log::{debug, error, info, warn};
use regex::escape;
use serde::de::DeserializeOwned;
use std::path::PathBuf;

use crate::parser::CodeParser;
use crate::prompts::{self, vuln_specific};
use crate::response::{response_json_schema, Response};

/// チャットAPI用のClientを生成して返す。
fn create_api_client() -> Client {
    let client_config = ClientConfig::default().with_chat_options(
        ChatOptions::default()
            .with_response_format(JsonSpec::new("json_object", response_json_schema())),
    );
    Client::builder().with_config(client_config).build()
}

/// チャットリクエストを実行し、応答内容（文字列）を返す。
async fn execute_chat_request(
    client: &Client,
    model: &str,
    chat_req: ChatRequest,
) -> Result<String> {
    let chat_res = client.exec_chat(model, chat_req, None).await?;
    match chat_res.content_text_as_str() {
        Some(content) => Ok(content.to_string()),
        None => {
            error!("Failed to get content text from chat response");
            Err(anyhow::anyhow!(
                "Failed to get content text from chat response"
            ))
        }
    }
}

/// JSON文字列をパースして型Tの構造体に変換する。
fn parse_json_response<T: DeserializeOwned>(chat_content: &str) -> Result<T> {
    match serde_json::from_str(chat_content) {
        Ok(response) => Ok(response),
        Err(e) => {
            debug!("Failed to parse JSON response: {}", e);
            debug!("Response content: {}", chat_content);
            Err(anyhow::anyhow!("Failed to parse JSON response: {}", e))
        }
    }
}

/// LLMを用いてファイルの脆弱性解析を行い、Responseを返す。
pub async fn analyze_file(
    file_path: &PathBuf,
    model: &str,
    files: &[PathBuf],
    verbosity: u8,
    context: &crate::parser::Context,
) -> Result<Response, Error> {
    info!("Performing initial analysis of {}", file_path.display());

    let mut parser = CodeParser::new()?;

    for file in files {
        if let Err(e) = parser.add_file(file) {
            warn!(
                "Failed to add file to parser {}: {}. Skipping file.",
                file.display(),
                e
            );
        }
    }

    let content = std::fs::read_to_string(file_path)?;
    if content.is_empty() {
        return Ok(Response {
            scratchpad: String::new(),
            analysis: String::new(),
            poc: String::new(),
            confidence_score: 0,
            vulnerability_types: vec![],
            context_code: vec![],
        });
    }

    // コンテキスト情報をプロンプトに含める
    let mut context_text = String::new();
    if !context.definitions.is_empty() {
        context_text.push_str("\nContext Definitions:\n");
        for def in &context.definitions {
            context_text.push_str(&format!(
                "\nFunction/Definition: {}\nCode:\n{}\n",
                def.name, def.source
            ));
        }
    }

    let prompt = format!(
        "File: {}\n\nContent:\n{}\n{}\n\n{}\n{}\n{}",
        file_path.display(),
        content,
        context_text,
        prompts::INITIAL_ANALYSIS_PROMPT_TEMPLATE,
        prompts::ANALYSIS_APPROACH_TEMPLATE,
        prompts::GUIDELINES_TEMPLATE,
    );
    debug!("[PROMPT]\n{}", prompt);

    let chat_req = ChatRequest::new(vec![
        ChatMessage::system("You are a security vulnerability analyzer. You must reply with exactly one JSON object that matches this schema: { \"scratchpad\": string, \"analysis\": string, \"poc\": string, \"confidence_score\": integer, \"vulnerability_types\": array of strings, \"context_code\": array of objects with { \"name\": string, \"reason\": string, \"code_line\": string } }. Do not include any explanatory text outside the JSON object."),
        ChatMessage::user(&prompt),
    ]);

    let json_client = create_api_client();
    let chat_content = execute_chat_request(&json_client, model, chat_req).await?;
    debug!("[LLM Response]\n{}", chat_content);
    let response: Response = parse_json_response(&chat_content)?;

    info!("Initial analysis complete");

    if response.confidence_score > 0 && !response.vulnerability_types.is_empty() {
        let vuln_info_map = vuln_specific::get_vuln_specific_info();

        for vuln_type in response.vulnerability_types.clone() {
            let vuln_info = vuln_info_map.get(&vuln_type).unwrap();

            let mut stored_code_definitions: Vec<(PathBuf, crate::parser::Definition)> = Vec::new();
            let mut previous_analysis = String::new();

            for iter in 0..2 {
                info!(
                    "Performing vuln-specific analysis iteration for {:?} (iteration {}/{})",
                    vuln_type,
                    iter + 1,
                    2
                );
                if verbosity > 0 {
                    println!(
                        "🔎 [{}] 脆弱性タイプ: {:?} の詳細解析 (iteration {}/{})",
                        file_path.display(),
                        vuln_type,
                        iter + 1,
                        2
                    );
                    if !stored_code_definitions.is_empty() {
                        println!("  解析コンテキスト関数:");
                        for (_, def) in &stored_code_definitions {
                            println!("    - {} ({}行)", def.name, def.source.lines().count());
                        }
                    }
                    println!("  考慮バイパス: {}", vuln_info.bypasses.join(", "));
                    println!(
                        "  追加プロンプト: {}",
                        &vuln_info.prompt.chars().take(40).collect::<String>()
                    );
                }

                let mut context_code = String::new();
                for (_, def) in &stored_code_definitions {
                    context_code.push_str(&format!(
                        "\nFunction: {}\nSource:\n{}\n",
                        def.name, def.source
                    ));
                }

                let prompt = format!(
                    "File: {}\n\nContent:\n{}\n\nContext Code:\n{}\n\nVulnerability Type: {:?}\n\nBypasses to Consider:\n{}\n\n{}\n{}\n{}\nPrevious Analysis:\n{}",
                    file_path.display(),
                    content,
                    context_code,
                    vuln_type,
                    vuln_info.bypasses.join("\n"),
                    vuln_info.prompt,
                    prompts::ANALYSIS_APPROACH_TEMPLATE,
                    prompts::GUIDELINES_TEMPLATE,
                    previous_analysis,
                );

                let chat_req = ChatRequest::new(vec![
                    ChatMessage::system(
                        "You are a security vulnerability analyzer. You must reply with exactly one JSON object that matches this schema: { \"scratchpad\": string, \"analysis\": string, \"poc\": string, \"confidence_score\": integer, \"vulnerability_types\": array of strings, \"context_code\": array of objects with { \"name\": string, \"reason\": string, \"code_line\": string } }. Do not include any explanatory text outside the JSON object.",
                    ),
                    ChatMessage::user(&prompt),
                ]);

                let json_client = create_api_client();
                let chat_content = execute_chat_request(&json_client, model, chat_req).await?;
                debug!("[LLM Response]\n{}", chat_content);
                let vuln_response: Response = parse_json_response(&chat_content)?;

                if verbosity > 0 {
                    debug!(
                        "  LLM応答: confidence_score={}, vulnerability_types={:?}",
                        vuln_response.confidence_score, vuln_response.vulnerability_types
                    );
                    println!(
                        "  analysis要約: {}",
                        &vuln_response.analysis.chars().take(60).collect::<String>()
                    );
                    if !vuln_response.context_code.is_empty() {
                        println!("  context_code:");
                        for ctx in &vuln_response.context_code {
                            println!("    - {}: {}", ctx.name, ctx.reason);
                        }
                    }
                    return Ok(vuln_response);
                }

                if vuln_response.context_code.is_empty() {
                    if verbosity == 0 {
                        return Ok(vuln_response);
                    }
                    break;
                }

                for context in vuln_response.context_code {
                    let escaped_name = escape(&context.name);
                    if !stored_code_definitions
                        .iter()
                        .any(|(_, def)| def.name == escaped_name)
                    {
                        match parser.find_definition(&escaped_name, file_path) {
                            Ok(Some(def)) => {
                                stored_code_definitions.push(def);
                            }
                            Ok(None) => {
                                debug!("No definition found for context: {}", escaped_name);
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to find definition for context {}: {}",
                                    escaped_name, e
                                );
                            }
                        }
                    }
                }

                previous_analysis = vuln_response.analysis;

                if vuln_response.confidence_score >= 95 {
                    break;
                }
            }
        }
    }
    if response.confidence_score > 0 && response.confidence_score < 95 {
        warn!(
            "信頼度スコア({})が低いため、{}は脆弱性が見つかりませんでした",
            response.confidence_score,
            file_path.display()
        );
        return Ok(Response {
            scratchpad: "脆弱性は見つかりませんでした".to_string(),
            analysis: "脆弱性は見つかりませんでした".to_string(),
            poc: String::new(),
            confidence_score: 0,
            vulnerability_types: vec![],
            context_code: Vec::new(),
        });
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{ContextCode, VulnType};
    use tempfile::NamedTempFile;

    #[cfg(feature = "snapshot-test")]
    #[tokio::test]
    async fn test_analyze_empty_file() -> Result<()> {
        let temp_file = NamedTempFile::new()?;

        let result = analyze_file(
            &PathBuf::from(temp_file.path()),
            "gpt-4o-mini",
            &[PathBuf::from(temp_file.path())],
            0,
            &crate::parser::Context {
                definitions: vec![],
            },
        )
        .await?;

        assert_eq!(result.scratchpad, String::new());
        assert_eq!(result.analysis, String::new());
        assert_eq!(result.poc, String::new());
        assert_eq!(result.confidence_score, 0);
        assert!(result.vulnerability_types.is_empty());
        assert!(result.context_code.is_empty());

        Ok(())
    }

    #[cfg(feature = "snapshot-test")]
    #[tokio::test]
    async fn test_analyze_hardcoded_password() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        std::fs::write(
            temp_file.path(),
            r#"
fn main() {
    let password = "hardcoded_password";
    println!("{}", password);
}
"#,
        )?;

        let result = analyze_file(
            &PathBuf::from(temp_file.path()),
            "gpt-4o-mini",
            &[PathBuf::from(temp_file.path())],
            0,
            &crate::parser::Context {
                definitions: vec![],
            },
        )
        .await?;

        assert!(!result.analysis.is_empty(), "Analysis should not be empty");
        assert!(
            result.confidence_score > 0,
            "Confidence score should be positive"
        );
        assert!(
            !result.vulnerability_types.is_empty(),
            "Should detect vulnerabilities"
        );
        assert!(
            !result.context_code.is_empty(),
            "Should include context code"
        );

        Ok(())
    }

    #[cfg(feature = "snapshot-test")]
    #[tokio::test]
    async fn test_analyze_authentication_function() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        std::fs::write(
            temp_file.path(),
            r#"
fn authenticate(input: &str) -> bool {
    let password = "hardcoded_password";
    input == password
}

fn main() {
    let user_input = "test";
    if authenticate(user_input) {
        println!("Authenticated!");
    }
}
"#,
        )?;

        let result = analyze_file(
            &PathBuf::from(temp_file.path()),
            "gpt-4o-mini",
            &[PathBuf::from(temp_file.path())],
            0,
            &crate::parser::Context {
                definitions: vec![],
            },
        )
        .await?;

        assert!(!result.analysis.is_empty(), "Analysis should not be empty");
        assert!(
            result.confidence_score > 0,
            "Confidence score should be positive"
        );
        assert!(
            !result.vulnerability_types.is_empty(),
            "Should detect vulnerabilities"
        );
        assert!(
            !result.context_code.is_empty(),
            "Should include context code"
        );

        Ok(())
    }
}
