use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::{trait_def::LLM, ChatMessage};

pub struct ChatGPT {
    model: String,
    base_url: String,
    client: Client,
    system_prompt: String,
}

impl ChatGPT {
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
impl LLM for ChatGPT {
    async fn chat(&self, prompt: &str) -> Result<String> {
        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<ChatMessage>,
            #[serde(rename = "response_format")]
            format: ResponseFormat,
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

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: format!("{}\n\nYou MUST respond with a valid JSON object containing the following fields:\n- scratchpad: string containing your analysis notes\n- analysis: string containing your final analysis\n- poc: string containing proof of concept or exploitation steps\n- confidence_score: integer between 0 and 100\n- vulnerability_types: array of strings, each being one of: LFI, RCE, SSRF, AFO, SQLI, XSS, IDOR\n- context_code: array of objects, each containing:\n  - name: string (function/method name)\n  - reason: string (why this code is relevant)\n  - code_line: string (the specific line of code)", self.system_prompt),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            },
        ];

        let request = Request {
            model: self.model.clone(),
            messages,
            format: ResponseFormat {
                format_type: "json_object".to_string(),
            },
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
            .await?
            .json::<Response>()
            .await?;

        Ok(response.choices[0].message.content.clone())
    }
}
