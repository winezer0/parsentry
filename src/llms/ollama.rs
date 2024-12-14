use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::trait_def::LLM;

pub struct Ollama {
    model: String,
    base_url: String,
    client: Client,
    system_prompt: String,
}

impl Ollama {
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
impl LLM for Ollama {
    async fn chat(&self, prompt: &str) -> Result<String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            prompt: String,
            system: String,
        }

        #[derive(Deserialize)]
        struct Response {
            response: String,
        }

        let request = Request {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            system: self.system_prompt.clone(),
        };

        let response = self
            .client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await?
            .json::<Response>()
            .await?;

        Ok(response.response)
    }
}

#[cfg(feature = "integration-tests")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
}
