use anyhow::{Error, Result};
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, JsonSpec};
use genai::{Client, ClientConfig};
use log::info;
use regex::escape;
use std::path::PathBuf;

use crate::parser::CodeParser;
use crate::prompts::{self, vuln_specific};
use crate::response::{response_json_schema, Response};

pub async fn analyze_file(
    file_path: &PathBuf,
    model: &str,
    files: &[PathBuf],
    verbosity: u8,
) -> Result<Response, Error> {
    info!("Performing initial analysis of {}", file_path.display());

    // Initialize parser
    let mut parser = CodeParser::new()?;

    // Add all files to the parser for cross-reference analysis
    for file in files {
        parser.add_file(file)?;
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

    let prompt = format!(
        "File: {}\n\nContent:\n{}\n\n{}\n{}\n{}",
        file_path.display(),
        content,
        prompts::INITIAL_ANALYSIS_PROMPT_TEMPLATE,
        prompts::ANALYSIS_APPROACH_TEMPLATE,
        prompts::GUIDELINES_TEMPLATE,
    );

    let chat_req = ChatRequest::new(vec![
        ChatMessage::system("You are a security vulnerability analyzer. Reply in JSON format"),
        ChatMessage::user(&prompt),
    ]);

    let client_config = ClientConfig::default().with_chat_options(
        ChatOptions::default()
            .with_response_format(JsonSpec::new("schema", response_json_schema())),
    );
    let json_client = Client::builder().with_config(client_config).build();
    let chat_res = json_client.exec_chat(model, chat_req, None).await?;
    let chat_content = match chat_res.content_text_as_str() {
        Some(content) => content,
        None => {
            log::error!("Failed to get content text from chat response");
            return Err(anyhow::anyhow!(
                "Failed to get content text from chat response"
            ));
        }
    };

    let response: Response = match serde_json::from_str(chat_content) {
        Ok(response) => response,
        Err(e) => {
            log::debug!("Failed to parse JSON response: {}", e);
            log::debug!("Response content: {}", chat_content);
            return Err(anyhow::anyhow!("Failed to parse JSON response: {}", e));
        }
    };
    info!("Initial analysis complete");

    // Secondary analysis for each vulnerability type
    if response.confidence_score > 0 && !response.vulnerability_types.is_empty() {
        let vuln_info_map = vuln_specific::get_vuln_specific_info();

        for vuln_type in response.vulnerability_types.clone() {
            let vuln_info = vuln_info_map.get(&vuln_type).unwrap();

            let mut stored_code_definitions = Vec::new();
            let mut previous_analysis = String::new();

            for _ in 0..7 {
                info!(
                    "Performing vuln-specific analysis iteration for {:?}",
                    vuln_type
                );

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
                        "You are a security vulnerability analyzer. Reply in JSON format",
                    ),
                    ChatMessage::user(&prompt),
                ]);

                let chat_res = json_client.exec_chat(model, chat_req, None).await?;
                let chat_content = match chat_res.content_text_as_str() {
                    Some(content) => content,
                    None => {
                        log::error!("Failed to get content text from chat response");
                        return Err(anyhow::anyhow!(
                            "Failed to get content text from chat response"
                        ));
                    }
                };

                let vuln_response: Response = match serde_json::from_str(chat_content) {
                    Ok(response) => response,
                    Err(e) => {
                        log::debug!("Failed to parse JSON response: {}", e);
                        log::debug!("Response content: {}", chat_content);
                        return Err(anyhow::anyhow!("Failed to parse JSON response: {}", e));
                    }
                };

                if verbosity > 0 {
                    return Ok(vuln_response);
                }

                if vuln_response.context_code.is_empty() {
                    if verbosity == 0 {
                        return Ok(vuln_response);
                    }
                    break;
                }

                // Extract new context code using Parser
                for context in vuln_response.context_code {
                    let escaped_name = escape(&context.name);
                    if !stored_code_definitions
                        .iter()
                        .any(|(_, def)| def.name == escaped_name)
                    {
                        if let Some(def) = parser.find_definition(&escaped_name, file_path) {
                            stored_code_definitions.push(def);
                        } else {
                            log::warn!(
                                "Failed to extract code definition for context: {}",
                                escaped_name
                            );
                            continue;
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

    Ok(response)
}
