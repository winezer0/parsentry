use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::trait_def::LLM;

pub struct Claude {
    model: String,
    base_url: String,
    client: Client,
    system_prompt: String,
}

impl Claude {
    pub fn new(model: String, base_url: String, system_prompt: String) -> Self {
        Self {
            model,
            base_url,
            client: Client::new(),
            system_prompt,
        }
    }
}

#[async_trait]
impl LLM for Claude {
    async fn chat(&self, prompt: &str) -> Result<String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<Message>,
        }

        #[derive(Serialize)]
        struct Message {
            role: String,
            content: Vec<Content>,
        }

        #[derive(Serialize)]
        struct Content {
            #[serde(rename = "type")]
            content_type: String,
            text: String,
        }

        #[derive(Deserialize)]
        struct Response {
            content: Vec<MessageContent>,
        }

        #[derive(Deserialize)]
        struct MessageContent {
            text: String,
        }

        let messages = vec![
            Message {
                role: "system".to_string(),
                content: vec![Content {
                    content_type: "text".to_string(),
                    text: self.system_prompt.clone(),
                }],
            },
            Message {
                role: "user".to_string(),
                content: vec![Content {
                    content_type: "text".to_string(),
                    text: prompt.to_string(),
                }],
            },
        ];

        let request = Request {
            model: self.model.clone(),
            messages,
        };

        let response = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("x-api-key", std::env::var("ANTHROPIC_API_KEY")?)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?
            .json::<Response>()
            .await?;

        Ok(response.content[0].text.clone())
    }
}

#[cfg(feature = "integration-tests")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
				use tokio;

				const TEST_MODEL: &str = "claude-3-opus-20240229";
				const TEST_SYSTEM_PROMPT: &str = "You are a helpful AI assistant.";
				const BASE_URL: &str = "https://api.anthropic.com/v1/messages";

				fn setup_claude() -> Claude {
								Claude::new(
												TEST_MODEL.to_string(),
												BASE_URL.to_string(),
												TEST_SYSTEM_PROMPT.to_string(),
								)
				}

				#[tokio::test]
				async fn test_chat_success() {
								let claude = setup_claude();
								let prompt = "What is 2+2?";
								
								let result = claude.chat(prompt).await;
								assert!(result.is_ok(), "Chat should succeed with valid API key");
								
								let response = result.unwrap();
								assert!(!response.is_empty(), "Response should not be empty");
				}

				#[tokio::test]
				async fn test_chat_invalid_api_key() {
								// Temporarily set invalid API key
								env::set_var("ANTHROPIC_API_KEY", "invalid_key");
								
								let claude = setup_claude();
								let prompt = "What is 2+2?";
								
								let result = claude.chat(prompt).await;
								assert!(result.is_err(), "Chat should fail with invalid API key");
				}

				#[test]
				fn test_claude_initialization() {
								let claude = setup_claude();
								assert_eq!(claude.model, TEST_MODEL);
								assert_eq!(claude.base_url, BASE_URL);
								assert_eq!(claude.system_prompt, TEST_SYSTEM_PROMPT);
				}
}
