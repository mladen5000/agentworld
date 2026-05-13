//! Minimal client for talking to a local [Ollama](https://ollama.ai) server.
//!
//! The surface is deliberately small: a `LlmClient` trait with one method,
//! `generate(request) -> Response`, and one concrete implementation
//! (`OllamaClient`) that hits the `/api/generate` endpoint. Tests can supply
//! their own in-memory client without spinning up a real server.
//!
//! ## Why a trait?
//!
//! The agent crates (`aw-agents`) take `Arc<dyn LlmClient>` so they're testable
//! without network access *and* swappable to a different backend later (e.g.
//! Anthropic API, mlx server) without churn.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Ollama returned non-success status {status}: {body}")]
    BadStatus { status: u16, body: String },
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// One generation request. Mirrors a useful subset of Ollama's `/api/generate`
/// input. `format: "json"` is exposed as a typed enum so callers don't
/// stringly-type the contract.
#[derive(Debug, Clone, Serialize)]
pub struct GenerateRequest {
    pub model: String,
    /// Combined system+user prompt. We don't model `system` separately because
    /// Ollama treats it as an optional field and the agents we build always
    /// have both — easier to assemble the full prompt in the agent.
    pub prompt: String,
    /// Optional system prompt; if present, Ollama uses its own template to
    /// prepend it. Useful for models that handle system prompts well.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Options>,
    /// When `Some(Format::Json)`, Ollama is asked to constrain output to a
    /// valid JSON document. Critical for agent reports that we parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
    /// We always disable streaming — the agents are batch consumers.
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Maximum tokens to generate. Ollama default is unbounded which is
    /// dangerous in agent loops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_predict: Option<i32>,
    /// Context window. Bigger → more input fits but slower / more RAM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_ctx: Option<i32>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Json,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateResponse {
    /// The model's text output. When `format: Json` was set, this is a JSON
    /// string the caller can parse.
    pub response: String,
    pub model: String,
    /// Server-reported wall-clock duration of the call (nanoseconds).
    #[serde(default)]
    pub total_duration: Option<u64>,
    #[serde(default)]
    pub eval_count: Option<i64>,
}

#[async_trait::async_trait]
pub trait LlmClient: Send + Sync {
    async fn generate(&self, req: GenerateRequest) -> Result<GenerateResponse, LlmError>;
}

/// Concrete client hitting Ollama over HTTP.
pub struct OllamaClient {
    base_url: String,
    http: reqwest::Client,
}

impl OllamaClient {
    pub fn new() -> Self {
        Self::with_base_url("http://127.0.0.1:11434")
    }

    pub fn with_base_url(url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            // Local model calls can be slow on first load; bound the wait.
            .timeout(Duration::from_secs(300))
            .build()
            .expect("reqwest client build");
        Self { base_url: url.into(), http }
    }
}

impl Default for OllamaClient {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl LlmClient for OllamaClient {
    async fn generate(&self, req: GenerateRequest) -> Result<GenerateResponse, LlmError> {
        let url = format!("{}/api/generate", self.base_url);
        let resp = self.http.post(&url).json(&req).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::BadStatus { status: status.as_u16(), body });
        }
        let parsed: GenerateResponse = resp.json().await?;
        Ok(parsed)
    }
}

/// In-memory test double. Records all calls; replies with whatever was queued.
pub mod mock {
    use std::sync::Mutex;

    use super::*;

    pub struct MockClient {
        replies: Mutex<Vec<String>>,
        calls: Mutex<Vec<GenerateRequest>>,
    }

    impl MockClient {
        pub fn new(replies: Vec<&str>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().rev().map(String::from).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn calls(&self) -> Vec<GenerateRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LlmClient for MockClient {
        async fn generate(&self, req: GenerateRequest) -> Result<GenerateResponse, LlmError> {
            self.calls.lock().unwrap().push(req.clone());
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| "(no reply queued)".to_string());
            Ok(GenerateResponse {
                response: reply,
                model: req.model,
                total_duration: Some(0),
                eval_count: Some(0),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_client_returns_queued_replies_in_order() {
        let m = mock::MockClient::new(vec!["first", "second"]);
        let r1 = m.generate(GenerateRequest {
            model: "test".into(),
            prompt: "a".into(),
            system: None,
            options: None,
            format: None,
            stream: false,
        }).await.unwrap();
        assert_eq!(r1.response, "first");
        let r2 = m.generate(GenerateRequest {
            model: "test".into(),
            prompt: "b".into(),
            system: None,
            options: None,
            format: None,
            stream: false,
        }).await.unwrap();
        assert_eq!(r2.response, "second");
        assert_eq!(m.calls().len(), 2);
    }

    #[tokio::test]
    async fn mock_client_returns_placeholder_when_exhausted() {
        let m = mock::MockClient::new(vec![]);
        let r = m.generate(GenerateRequest {
            model: "test".into(),
            prompt: "a".into(),
            system: None,
            options: None,
            format: None,
            stream: false,
        }).await.unwrap();
        assert_eq!(r.response, "(no reply queued)");
    }

    #[test]
    fn request_serializes_skipping_optionals() {
        let req = GenerateRequest {
            model: "gemma3:4b".into(),
            prompt: "hello".into(),
            system: None,
            options: None,
            format: None,
            stream: false,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"model\":\"gemma3:4b\""));
        assert!(!s.contains("system"));
        assert!(!s.contains("format"));
    }

    #[test]
    fn request_with_json_format_serializes_correctly() {
        let req = GenerateRequest {
            model: "x".into(),
            prompt: "y".into(),
            system: Some("be brief".into()),
            options: Some(Options { temperature: Some(0.2), num_predict: Some(256), num_ctx: Some(4096) }),
            format: Some(Format::Json),
            stream: false,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"format\":\"json\""));
        assert!(s.contains("\"temperature\":0.2"));
        assert!(s.contains("\"num_predict\":256"));
        assert!(s.contains("\"system\":\"be brief\""));
    }
}
