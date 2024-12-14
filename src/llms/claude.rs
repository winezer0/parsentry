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
