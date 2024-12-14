use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait LLM {
    async fn chat(&self, prompt: &str) -> Result<String>;
}

// ChatGPT Message type
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

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
            messages: Vec<ChatMessage>,
        }

        #[derive(Deserialize)]
        struct Response {
            content: Vec<Choice>,
        }

        #[derive(Deserialize)]
        struct Choice {
            text: String,
        }

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: self.system_prompt.clone(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
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
            .json(&request)
            .send()
            .await?
            .json::<Response>()
            .await?;

        Ok(response.content[0].text.clone())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_initialize_llm_claude() {
        let system_prompt = "test prompt";
        let result = initialize_llm("claude", system_prompt);
        assert!(result.is_ok());
        
        // Test default values
        assert_eq!(
            env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-3.5-sonnet-20241022".to_string()),
            "claude-3.5-sonnet-20241022"
        );
        assert_eq!(
            env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| "https://api.anthropic.com/v1/messages".to_string()),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[tokio::test]
    async fn test_initialize_llm_gpt() {
        let system_prompt = "test prompt";
        let result = initialize_llm("gpt", system_prompt);
        assert!(result.is_ok());
        
        // Test default values
        assert_eq!(
            env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-latest".to_string()),
            "gpt-4o-latest"
        );
        assert_eq!(
            env::var("OPENAI_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string()),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[tokio::test]
    async fn test_initialize_llm_ollama() {
        let system_prompt = "test prompt";
        let result = initialize_llm("ollama", system_prompt);
        assert!(result.is_ok());
        
        // Test default values
        assert_eq!(
            env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama2".to_string()),
            "llama2"
        );
        assert_eq!(
            env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434/api/generate".to_string()),
            "http://localhost:11434/api/generate"
        );
    }

    #[tokio::test]
    async fn test_initialize_llm_invalid() {
        let system_prompt = "test prompt";
        let result = initialize_llm("invalid", system_prompt);
        assert!(result.is_err());
        
        match result {
            Ok(_) => panic!("Expected error for invalid LLM type"),
            Err(e) => assert!(e.to_string().contains("Invalid LLM argument")),
        }
    }

    #[tokio::test]
    async fn test_claude_new() {
        let model = "test-model".to_string();
        let base_url = "http://test-url".to_string();
        let system_prompt = "test-prompt".to_string();
        
        let claude = Claude::new(
            model.clone(),
            base_url.clone(),
            system_prompt.clone(),
        );
        
        assert_eq!(claude.model, model);
        assert_eq!(claude.base_url, base_url);
        assert_eq!(claude.system_prompt, system_prompt);
    }

    #[tokio::test]
    async fn test_chatgpt_new() {
        let model = "test-model".to_string();
        let base_url = "http://test-url".to_string();
        let system_prompt = "test-prompt".to_string();
        
        let gpt = ChatGPT::new(
            model.clone(),
            base_url.clone(),
            system_prompt.clone(),
        );
        
        assert_eq!(gpt.model, model);
        assert_eq!(gpt.base_url, base_url);
        assert_eq!(gpt.system_prompt, system_prompt);
    }

    #[tokio::test]
    async fn test_ollama_new() {
        let model = "test-model".to_string();
        let base_url = "http://test-url".to_string();
        let system_prompt = "test-prompt".to_string();
        
        let ollama = Ollama::new(
            model.clone(),
            base_url.clone(),
            system_prompt.clone(),
        );
        
        assert_eq!(ollama.model, model);
        assert_eq!(ollama.base_url, base_url);
        assert_eq!(ollama.system_prompt, system_prompt);
    }

    #[tokio::test]
    async fn test_chat_message_serialization() {
        let message = ChatMessage {
            role: "user".to_string(),
            content: "test message".to_string(),
        };
        
        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: ChatMessage = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(message.role, deserialized.role);
        assert_eq!(message.content, deserialized.content);
    }
}
