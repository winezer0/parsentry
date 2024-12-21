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
    async fn chat(
        &self,
        messages: &[ChatMessage],
        response_model: Option<String>,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<ChatMessage>,
            max_tokens: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            response_format: Option<ResponseFormat>,
        }

        #[derive(Serialize)]
        struct ResponseFormat {
            #[serde(rename = "type")]
            format_type: String,
        }

        #[derive(Deserialize)]
        struct Response {
            choices: Vec<Choice>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: ChatMessage,
        }

        let mut all_messages = vec![ChatMessage {
            role: "system".to_string(),
            content: self.system_prompt.clone(),
        }];
        all_messages.extend_from_slice(messages);

        let response_format = if messages.iter().any(|msg| msg.content.contains("json")) {
            Some(ResponseFormat {
                format_type: "json_object".to_string(),
            })
        } else {
            response_model.clone().map(|_| ResponseFormat {
                format_type: "json_object".to_string(),
            })
        };

        let request = Request {
            model: self.model.clone(),
            messages: all_messages,
            max_tokens: 1024,
            response_format,
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
                if response_model.is_some() {
                    let json_str = response.choices[0].message.content.clone();
                    let parsed_model: Result<_, _> = serde_json::from_str(&json_str);
                    match parsed_model {
                        Ok(model) => Ok(model),
                        Err(parse_error) => {
                            println!("JSON Parsing error: {}", parse_error);
                            println!("Failed to parse response: {}", response_text);
                            Err(parse_error.into())
                        }
                    }
                } else {
                    Ok(response.choices[0].message.content.clone())
                }
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

        let result = openai.chat(&messages, None).await;
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

        let result = openai.chat(&messages, None).await;
        assert!(result.is_err(), "Chat should fail with invalid API key");
    }
}
