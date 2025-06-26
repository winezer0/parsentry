use anyhow::{Error, Result};
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, JsonSpec};
use genai::resolver::{AuthData, Endpoint, ServiceTargetResolver};
use genai::{Client, ClientConfig};
use genai::{ModelIden, ServiceTarget, adapter::AdapterKind};
use log::{debug, error, info, warn};
use regex::escape;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use crate::locales::Language;
use crate::parser::CodeParser;
use crate::prompts::{self, vuln_specific};
use crate::response::{Response, response_json_schema};
use crate::security_patterns::{PatternType, SecurityRiskPatterns, PatternMatch};

fn save_debug_file(
    output_dir: &Option<PathBuf>,
    file_path: &PathBuf,
    suffix: &str,
    content: &str,
) -> Result<()> {
    if let Some(dir) = output_dir {
        let debug_dir = dir.join("debug");
        fs::create_dir_all(&debug_dir)?;

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Add timestamp to ensure uniqueness across multiple LLM calls
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let debug_file_name = format!("{}_{}_{}.txt", file_name, suffix, timestamp);
        let debug_path = debug_dir.join(debug_file_name);

        fs::write(&debug_path, content)?;
        info!("Debug file saved: {}", debug_path.display());
    }
    Ok(())
}

fn create_api_client(api_base_url: Option<&str>) -> Client {
    let client_config = ClientConfig::default().with_chat_options(
        ChatOptions::default()
            .with_response_format(JsonSpec::new("json_object", response_json_schema())),
    );

    let mut client_builder = Client::builder().with_config(client_config);

    // Add custom service target resolver if base URL is provided
    if let Some(base_url) = api_base_url {
        let target_resolver = create_custom_target_resolver(base_url);
        client_builder = client_builder.with_service_target_resolver(target_resolver);
    }

    client_builder.build()
}

fn create_custom_target_resolver(base_url: &str) -> ServiceTargetResolver {
    let base_url_owned = base_url.to_string();
    let disable_v1_path = std::env::var("PARSENTRY_DISABLE_V1_PATH").is_ok();

    ServiceTargetResolver::from_resolver_fn(
        move |service_target: ServiceTarget| -> Result<ServiceTarget, genai::resolver::Error> {
            let ServiceTarget { model, .. } = service_target;

            // Check if we should use a different adapter to avoid /v1 path appending
            let (adapter_kind, final_endpoint) = if disable_v1_path {
                // Use Groq adapter which doesn't append /v1/chat/completions
                // This allows us to use the full URL as-is
                println!(
                    "🔍 Debug: Using Groq adapter (PARSENTRY_DISABLE_V1_PATH=true) with URL: {}",
                    base_url_owned
                );
                (AdapterKind::Groq, base_url_owned.clone())
            } else {
                // Default behavior: OpenAI adapter automatically adds /v1/chat/completions
                println!(
                    "🔍 Debug: Using OpenAI adapter with base URL: {}",
                    base_url_owned
                );
                (AdapterKind::OpenAI, base_url_owned.clone())
            };

            let endpoint = Endpoint::from_owned(final_endpoint);
            let model = ModelIden::new(adapter_kind, model.model_name);

            // Use the OPENAI_API_KEY environment variable as the new key when using custom URL
            let auth = AuthData::from_env("OPENAI_API_KEY");

            Ok(ServiceTarget {
                endpoint,
                auth,
                model,
            })
        },
    )
}

async fn execute_chat_request(
    client: &Client,
    model: &str,
    chat_req: ChatRequest,
) -> Result<String> {
    let result = timeout(Duration::from_secs(240), async {
        client.exec_chat(model, chat_req, None).await
    })
    .await;

    match result {
        Ok(Ok(chat_res)) => match chat_res.content_text_as_str() {
            Some(content) => Ok(content.to_string()),
            None => {
                error!("Failed to get content text from chat response");
                Err(anyhow::anyhow!(
                    "Failed to get content text from chat response"
                ))
            }
        },
        Ok(Err(e)) => {
            error!("Chat request failed: {}", e);
            Err(e.into())
        }
        Err(_) => {
            error!("Chat request timed out after 240 seconds");
            Err(anyhow::anyhow!("Chat request timed out after 180 seconds"))
        }
    }
}

async fn execute_chat_request_with_retry(
    client: &Client,
    model: &str,
    chat_req: ChatRequest,
    max_retries: u32,
) -> Result<String> {
    let mut last_error = None;

    for attempt in 0..=max_retries {
        if attempt > 0 {
            warn!(
                "Retrying chat request (attempt {}/{})",
                attempt + 1,
                max_retries + 1
            );
            // 指数バックオフで待機
            tokio::time::sleep(Duration::from_millis(1000 * (1 << attempt))).await;
        }

        match execute_chat_request(client, model, chat_req.clone()).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                warn!("Chat request failed on attempt {}: {}", attempt + 1, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All retry attempts failed")))
}

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

pub async fn analyze_file(
    file_path: &PathBuf,
    model: &str,
    files: &[PathBuf],
    verbosity: u8,
    context: &crate::parser::Context,
    min_confidence: i32,
    debug: bool,
    output_dir: &Option<PathBuf>,
    api_base_url: Option<&str>,
    language: &Language,
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
    
    // Skip files with more than 50,000 characters
    if content.len() > 50_000 {
        return Ok(Response {
            scratchpad: String::new(),
            analysis: String::new(),
            poc: String::new(),
            confidence_score: 0,
            vulnerability_types: vec![],
            par_analysis: crate::response::ParAnalysis {
                principals: vec![],
                actions: vec![],
                resources: vec![],
                policy_violations: vec![],
            },
            remediation_guidance: crate::response::RemediationGuidance {
                policy_enforcement: vec![],
            },
            file_path: Some(file_path.to_string_lossy().to_string()),
            pattern_description: Some("File too large for analysis".to_string()),
            matched_source_code: None,
            full_source_code: None,
        });
    }
    
    if content.is_empty() {
        return Ok(Response {
            scratchpad: String::new(),
            analysis: String::new(),
            poc: String::new(),
            confidence_score: 0,
            vulnerability_types: vec![],
            par_analysis: crate::response::ParAnalysis {
                principals: vec![],
                actions: vec![],
                resources: vec![],
                policy_violations: vec![],
            },
            remediation_guidance: crate::response::RemediationGuidance {
                policy_enforcement: vec![],
            },
            file_path: Some(file_path.to_string_lossy().to_string()),
            pattern_description: Some("Empty file analysis".to_string()),
            matched_source_code: None,
            full_source_code: Some(String::new()),
        });
    }

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
        prompts::get_initial_analysis_prompt_template(language),
        prompts::get_analysis_approach_template(language),
        prompts::get_guidelines_template(language),
    );
    debug!("[PROMPT]\n{}", prompt);

    // Save debug input if debug mode is enabled
    if debug {
        let debug_content = format!(
            "=== INITIAL ANALYSIS PROMPT ===\nModel: {}\nFile: {}\nTimestamp: {}\n\n{}",
            model,
            file_path.display(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            prompt
        );
        if let Err(e) = save_debug_file(output_dir, file_path, "01_initial_prompt", &debug_content)
        {
            warn!("Failed to save debug input file: {}", e);
        }
    }

    let chat_req = ChatRequest::new(vec![
        ChatMessage::system(
            "You are a security vulnerability analyzer. You must reply with exactly one JSON object that matches the PAR analysis schema with scratchpad, analysis, poc, confidence_score, vulnerability_types, par_analysis (with principals, actions, resources, policy_violations), and remediation_guidance fields. Do not include any explanatory text outside the JSON object.",
        ),
        ChatMessage::user(&prompt),
    ]);

    let json_client = create_api_client(api_base_url);
    let chat_content = execute_chat_request(&json_client, model, chat_req).await?;
    debug!("[LLM Response]\n{}", chat_content);

    // Save debug output if debug mode is enabled
    if debug {
        let debug_content = format!(
            "=== INITIAL ANALYSIS RESPONSE ===\nModel: {}\nFile: {}\nTimestamp: {}\n\n{}",
            model,
            file_path.display(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chat_content
        );
        if let Err(e) =
            save_debug_file(output_dir, file_path, "02_initial_response", &debug_content)
        {
            warn!("Failed to save debug output file: {}", e);
        }
    }
    let mut response: Response = parse_json_response(&chat_content)?;

    response.confidence_score =
        crate::response::Response::normalize_confidence_score(response.confidence_score);

    // Clean up and validate the response
    response.sanitize();

    info!("Initial analysis complete");

    if response.confidence_score >= min_confidence && !response.vulnerability_types.is_empty() {
        let vuln_info_map = vuln_specific::get_vuln_specific_info();

        for vuln_type in response.vulnerability_types.clone() {
            let vuln_info = vuln_info_map.get(&vuln_type).unwrap();

            let mut stored_code_definitions: Vec<(PathBuf, crate::parser::Definition)> = Vec::new();

            {
                info!("Performing vuln-specific analysis for {:?}", vuln_type);
                if verbosity > 0 {
                    println!(
                        "🔎 [{}] 脆弱性タイプ: {:?} の詳細解析",
                        file_path.display(),
                        vuln_type
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
                    "File: {}\n\nContent:\n{}\n\nContext Code:\n{}\n\nVulnerability Type: {:?}\n\nBypasses to Consider:\n{}\n\n{}\n{}\n{}",
                    file_path.display(),
                    content,
                    context_code,
                    vuln_type,
                    vuln_info.bypasses.join("\n"),
                    vuln_info.prompt,
                    prompts::get_analysis_approach_template(language),
                    prompts::get_guidelines_template(language),
                );

                // Save debug input if debug mode is enabled
                if debug {
                    let debug_content = format!(
                        "=== VULNERABILITY-SPECIFIC ANALYSIS PROMPT ===\nModel: {}\nFile: {}\nVulnerability Type: {:?}\nTimestamp: {}\n\n{}",
                        model,
                        file_path.display(),
                        vuln_type,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        prompt
                    );
                    let debug_suffix = format!("03_vuln_prompt_{:?}", vuln_type);
                    if let Err(e) =
                        save_debug_file(output_dir, file_path, &debug_suffix, &debug_content)
                    {
                        warn!("Failed to save debug input file: {}", e);
                    }
                }

                let chat_req = ChatRequest::new(vec![
                    ChatMessage::system(
                        "You are a security vulnerability analyzer. You must reply with exactly one JSON object that matches this schema: { \"scratchpad\": string, \"analysis\": string, \"poc\": string, \"confidence_score\": integer, \"vulnerability_types\": array of strings, \"context_code\": array of objects with { \"name\": string, \"reason\": string, \"code_line\": string } }. Do not include any explanatory text outside the JSON object.",
                    ),
                    ChatMessage::user(&prompt),
                ]);

                let json_client = create_api_client(api_base_url);
                let chat_content =
                    execute_chat_request_with_retry(&json_client, model, chat_req, 2).await?;
                debug!("[LLM Response]\n{}", chat_content);

                // Save debug output if debug mode is enabled
                if debug {
                    let debug_content = format!(
                        "=== VULNERABILITY-SPECIFIC ANALYSIS RESPONSE ===\nModel: {}\nFile: {}\nVulnerability Type: {:?}\nTimestamp: {}\n\n{}",
                        model,
                        file_path.display(),
                        vuln_type,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        chat_content
                    );
                    let debug_suffix = format!("04_vuln_response_{:?}", vuln_type);
                    if let Err(e) =
                        save_debug_file(output_dir, file_path, &debug_suffix, &debug_content)
                    {
                        warn!("Failed to save debug output file: {}", e);
                    }
                }
                let mut vuln_response: Response = parse_json_response(&chat_content)?;

                vuln_response.confidence_score =
                    crate::response::Response::normalize_confidence_score(
                        vuln_response.confidence_score,
                    );

                if verbosity > 0 {
                    debug!(
                        "  LLM応答: confidence_score={}, vulnerability_types={:?}",
                        vuln_response.confidence_score, vuln_response.vulnerability_types
                    );
                    println!(
                        "  analysis要約: {}",
                        &vuln_response.analysis.chars().take(60).collect::<String>()
                    );
                    if !vuln_response.par_analysis.policy_violations.is_empty() {
                        println!("  policy_violations:");
                        for violation in &vuln_response.par_analysis.policy_violations {
                            println!(
                                "    - {}: {}",
                                violation.rule_id, violation.rule_description
                            );
                        }
                    }
                    return Ok(vuln_response);
                }

                if vuln_response.par_analysis.policy_violations.is_empty() {
                    if verbosity == 0 {
                        return Ok(vuln_response);
                    }
                    break;
                }

                // Get language for pattern detection
                let filename = file_path.to_string_lossy();
                let language =
                    crate::file_classifier::FileClassifier::classify(&filename, &content);
                let _patterns = SecurityRiskPatterns::new(language);

                // Extract identifiers from PAR analysis for context building
                let mut identifiers_to_search = Vec::new();

                for principal in &vuln_response.par_analysis.principals {
                    identifiers_to_search
                        .push((principal.identifier.clone(), PatternType::Principal));
                }
                for action in &vuln_response.par_analysis.actions {
                    identifiers_to_search.push((action.identifier.clone(), PatternType::Action));
                }
                for resource in &vuln_response.par_analysis.resources {
                    identifiers_to_search
                        .push((resource.identifier.clone(), PatternType::Resource));
                }

                for (identifier, pattern_type) in identifiers_to_search {
                    let escaped_name = escape(&identifier);
                    if !stored_code_definitions
                        .iter()
                        .any(|(_, def)| def.name == escaped_name)
                    {
                        match pattern_type {
                            PatternType::Principal => {
                                // For principals, use find_references to track data flow forward
                                match parser.find_references(&escaped_name) {
                                    Ok(refs) => {
                                        stored_code_definitions.extend(refs);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to find references for principal context {}: {}",
                                            escaped_name, e
                                        );
                                    }
                                }
                            }
                            PatternType::Action => {
                                // For actions, use bidirectional tracking to understand both input and output
                                match parser.find_bidirectional(&escaped_name, file_path) {
                                    Ok(bidirectional_results) => {
                                        stored_code_definitions.extend(bidirectional_results);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to find bidirectional context for action {}: {}",
                                            escaped_name, e
                                        );
                                    }
                                }
                            }
                            PatternType::Resource => {
                                // For resources, use find_definition to track data origin
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
                    }
                }
            }
        }
    }
    
    // Add enhanced report information to response
    response.file_path = Some(file_path.to_string_lossy().to_string());
    response.full_source_code = Some(content);
    // For file-based analysis, no specific pattern or matched code
    response.pattern_description = Some("Full file analysis".to_string());
    response.matched_source_code = None;
    
    Ok(response)
}

pub async fn analyze_pattern(
    file_path: &PathBuf,
    pattern_match: &PatternMatch,
    model: &str,
    files: &[PathBuf],
    _verbosity: u8,
    min_confidence: i32,
    debug: bool,
    output_dir: &Option<PathBuf>,
    api_base_url: Option<&str>,
    language: &Language,
) -> Result<Option<Response>, Error> {
    info!(
        "Analyzing pattern '{}' in file {}",
        pattern_match.pattern_config.description,
        file_path.display()
    );

    let mut parser = CodeParser::new()?;

    // Add files for context parsing
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
    
    // Skip files with more than 50,000 characters
    if content.len() > 50_000 {
        return Ok(None);
    }
    
    // Extract context from file
    let context = parser.build_context_from_file(file_path)?;

    // Build pattern-specific prompt
    let pattern_context = format!(
        "Pattern Type: {:?}\nPattern Description: {}\nMatched Code: {}\nAttack Vectors: {}",
        pattern_match.pattern_type,
        pattern_match.pattern_config.description,
        pattern_match.matched_text,
        pattern_match.pattern_config.attack_vector.join(", ")
    );

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
        "File: {}\n\nPattern Analysis:\n{}\n\nFull File Content:\n{}\n{}\n\n{}\n{}\n{}",
        file_path.display(),
        pattern_context,
        content,
        context_text,
        prompts::get_initial_analysis_prompt_template(language),
        prompts::get_analysis_approach_template(language),
        prompts::get_guidelines_template(language)
    );

    debug!("[PATTERN-BASED PROMPT]\n{}", prompt);

    // Save debug input if debug mode is enabled
    if debug {
        let debug_content = format!(
            "=== PATTERN-BASED ANALYSIS PROMPT ===\nModel: {}\nFile: {}\nPattern: {}\nTimestamp: {}\n\n{}",
            model,
            file_path.display(),
            pattern_match.pattern_config.description,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            prompt
        );
        if let Err(e) = save_debug_file(
            output_dir,
            file_path,
            &format!("pattern_{}_prompt", pattern_match.pattern_config.description.replace(" ", "_")),
            &debug_content,
        ) {
            warn!("Failed to save debug input file: {}", e);
        }
    }

    let chat_req = ChatRequest::new(vec![
        ChatMessage::system(
            "You are a security vulnerability analyzer. You must reply with exactly one JSON object that matches the PAR analysis schema with scratchpad, analysis, poc, confidence_score, vulnerability_types, par_analysis (with principals, actions, resources, policy_violations), and remediation_guidance fields. Do not include any explanatory text outside the JSON object.",
        ),
        ChatMessage::user(&prompt),
    ]);

    let json_client = create_api_client(api_base_url);
    let chat_content = execute_chat_request(&json_client, model, chat_req).await?;
    debug!("[PATTERN LLM Response]\n{}", chat_content);

    // Save debug output if debug mode is enabled
    if debug {
        let debug_content = format!(
            "=== PATTERN-BASED ANALYSIS RESPONSE ===\nModel: {}\nFile: {}\nPattern: {}\nTimestamp: {}\n\n{}",
            model,
            file_path.display(),
            pattern_match.pattern_config.description,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chat_content
        );
        if let Err(e) = save_debug_file(
            output_dir,
            file_path,
            &format!("pattern_{}_response", pattern_match.pattern_config.description.replace(" ", "_")),
            &debug_content,
        ) {
            warn!("Failed to save debug output file: {}", e);
        }
    }

    let mut response: Response = parse_json_response(&chat_content)?;

    response.confidence_score =
        crate::response::Response::normalize_confidence_score(response.confidence_score);

    // Clean up and validate the response
    response.sanitize();

    // Add pattern-specific metadata to response
    if response.confidence_score >= min_confidence {
        // Enhance response with pattern information
        response.par_analysis.policy_violations.iter_mut().for_each(|violation| {
            if !violation.rule_description.contains(&pattern_match.pattern_config.description) {
                violation.rule_description = format!(
                    "{} (Pattern: {})",
                    violation.rule_description,
                    pattern_match.pattern_config.description
                );
            }
        });
    }

    // Add enhanced report information to response
    response.file_path = Some(file_path.to_string_lossy().to_string());
    response.pattern_description = Some(pattern_match.pattern_config.description.clone());
    response.matched_source_code = Some(pattern_match.matched_text.clone());
    response.full_source_code = Some(content);

    info!(
        "Pattern analysis complete for '{}' with confidence: {}",
        pattern_match.pattern_config.description,
        response.confidence_score
    );

    Ok(Some(response))
}
