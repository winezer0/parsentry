use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::{ChatMessage, LLM};

pub struct OpenAI {
    pub model: String,
    pub base_url: String,
    pub client: Client,
    pub system_prompt: String,
}

impl OpenAI {
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
impl LLM for OpenAI {
    async fn chat(&self, prompt: &[ChatMessage]) -> Result<String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<ChatMessage>,
        }

        #[derive(Deserialize)]
        struct Response {
            choices: Vec<Choice>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: ChatMessage,
        }

        let mut messages = vec![ChatMessage {
            role: "system".to_string(),
            content: self.system_prompt.clone(),
        }];
        messages.extend_from_slice(prompt);

        let request = Request {
            model: self.model.clone(),
            messages,
        };

        let response = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!("Bearer {}", std::env::var("OPENAI_API_KEY")?),
            )
            .json(&request)
            .send()
            .await?;

        // Print the raw response for debugging
        let response_text = response.text().await?;
        println!("Raw response: {}", response_text);

        match serde_json::from_str::<Response>(&response_text) {
            Ok(response) => {
                if response.choices.is_empty() {
                    return Err(anyhow::anyhow!("No choices in response"));
                }
                Ok(response.choices[0].message.content.clone())
            }
            Err(e) => {
                println!("JSON parsing error: {}", e);
                println!("Failed to parse response: {}", response_text);
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::dotenv;
    use std::env;
    use tokio;

    const TEST_MODEL: &str = "gpt-4o";
    const TEST_SYSTEM_PROMPT: &str = "You are a helpful AI assistant.";
    const BASE_URL: &str = "https://api.openai.com/v1/chat/completions";

    fn setup_openai() -> OpenAI {
        dotenv().ok();
        OpenAI::new(
            TEST_MODEL.to_string(),
            BASE_URL.to_string(),
            TEST_SYSTEM_PROMPT.to_string(),
        )
    }

    #[tokio::test]
    async fn test_chat_success() {
        dotenv().ok();
        let openai = setup_openai();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "What is 2+2?".to_string(),
        }];

        let result = openai.chat(&messages).await;
        assert!(result.is_ok(), "Chat should succeed with valid API key");

        let response = result.unwrap();
        assert!(!response.is_empty(), "Response should not be empty");
    }

    #[tokio::test]
    async fn test_chat_invalid_api_key() {
        // Temporarily set invalid API key
        env::set_var("OPENAI_API_KEY", "invalid_key");

        let openai = setup_openai();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "What is 2+2?".to_string(),
        }];

        let result = openai.chat(&messages).await;
        assert!(result.is_err(), "Chat should fail with invalid API key");
    }
}
