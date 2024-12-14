use super::*;
use std::env;

#[tokio::test]
async fn test_initialize_llm_claude() {
    let system_prompt = "test prompt";
    let result = initialize_llm("claude", system_prompt);
    assert!(result.is_ok());
    
    // Test default values
    assert_eq!(
        env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-3-sonnet-20240229".to_string()),
        "claude-3-sonnet-20240229"
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
        env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4-turbo-preview".to_string()),
        "gpt-4-turbo-preview"
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
