use anyhow::{Error, Result};
use log::info;
use std::path::PathBuf;

use crate::llm::LLM;
use crate::prompts::{self, vuln_specific};
use crate::response::Response;
use crate::symbol_finder::{CodeDefinition, SymbolExtractor};

pub async fn analyze_file(
    file_path: &PathBuf,
    llm: &Box<dyn LLM>,
    code_extractor: &mut SymbolExtractor,
    files: &[PathBuf],
    verbosity: u8,
) -> Result<Response, Error> {
    info!("Performing initial analysis of {}", file_path.display());

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

    let chat_response = llm.chat(&prompt).await?;
    let response: Response = serde_json::from_str(&chat_response)?;
    info!("Initial analysis complete");

    // Secondary analysis for each vulnerability type
    if response.confidence_score > 0 && !response.vulnerability_types.is_empty() {
        let vuln_info_map = vuln_specific::get_vuln_specific_info();

        for vuln_type in response.vulnerability_types.clone() {
            let vuln_info = vuln_info_map.get(&vuln_type).unwrap();

            let mut stored_code_definitions: Vec<CodeDefinition> = Vec::new();
            let mut previous_analysis = String::new();

            for _ in 0..7 {
                info!(
                    "Performing vuln-specific analysis iteration for {:?}",
                    vuln_type
                );

                let mut context_code = String::new();
                for def in &stored_code_definitions {
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

                let chat_response = llm.chat(&prompt).await?;
                let vuln_response: Response = serde_json::from_str(&chat_response)?;

                if verbosity > 0 {
                    return Ok(vuln_response);
                }

                if vuln_response.context_code.is_empty() {
                    if verbosity == 0 {
                        return Ok(vuln_response);
                    }
                    break;
                }

                // Extract new context code
                for context in vuln_response.context_code {
                    if !stored_code_definitions
                        .iter()
                        .any(|def| def.name == context.name)
                    {
                        if let Some(def) =
                            code_extractor.extract(&context.name, &context.code_line, files)
                        {
                            stored_code_definitions.push(def);
                        }
                    }
                }

                previous_analysis = vuln_response.analysis;
            }
        }
    }

    Ok(response)
}
