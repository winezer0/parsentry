use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait LLM {
    async fn chat(&self, prompt: &str) -> Result<String>;
}
