mod chatgpt;
mod claude;
mod ollama;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use self::{chatgpt::ChatGPT, claude::Claude, ollama::Ollama};

#[async_trait]
pub trait LLM {
				async fn chat(&self, prompt: &str) -> Result<String>;
}

// ChatGPT Message type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
				pub role: String,
				pub content: String,
}

pub fn initialize_llm(llm_arg: &str, system_prompt: &str) -> Result<Box<dyn LLM>> {
    match llm_arg.to_lowercase().as_str() {
        "claude" => {
            let model = std::env::var("ANTHROPIC_MODEL")
                .unwrap_or_else(|_| "claude-3.5-sonnet-20241022".to_string());
            let base_url = std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string());
            Ok(Box::new(Claude::new(
                model,
                base_url,
                system_prompt.to_string(),
            )))
        }
        "gpt" => {
            let model =
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-latest".to_string());
            let base_url = std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
            Ok(Box::new(ChatGPT::new(
                model,
                base_url,
                system_prompt.to_string(),
            )))
        }
        "ollama" => {
            let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama2".to_string());
            let base_url = std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:11434/api/generate".to_string());
            Ok(Box::new(Ollama::new(
                model,
                base_url,
                system_prompt.to_string(),
            )))
        }
        _ => anyhow::bail!(
            "Invalid LLM argument: {}. Valid options are: claude, gpt, ollama",
            llm_arg
        ),
    }
}
