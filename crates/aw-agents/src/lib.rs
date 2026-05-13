//! Agents that consume Layer 2 events and Layer 3 graphs and produce
//! human-readable analyses via a local LLM.
//!
//! Three concrete agents live here:
//!
//! - [`timeline_narrator::TimelineNarrator`] — chronological prose summary.
//! - [`process_anomaly::ProcessAnomalyDetector`] — flags suspicious processes
//!   by lineage / name / uid.
//! - [`network_reviewer::NetworkReviewer`] — flags notable network conversations.
//!
//! All agents share a [`Report`] return shape and use the
//! [`aw_llm::LlmClient`] trait, so tests can supply a mock and never need a
//! live Ollama instance.

use std::sync::Arc;

use aw_llm::LlmClient;
use serde::{Deserialize, Serialize};

pub mod input;
pub mod network_reviewer;
pub mod process_anomaly;
pub mod timeline_narrator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Short human-readable summary (1–3 sentences).
    pub summary: String,
    /// Structured detail. Shape depends on the agent — see individual agents'
    /// docs. Stored as JSON so the CLI can pretty-print it without knowing
    /// the agent.
    pub details: serde_json::Value,
    /// Which model generated this. Useful when running multiple models.
    pub model: String,
}

/// Common config knobs every agent accepts.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub model: String,
    /// Cap on input items (events, processes, connections) we feed the model.
    /// Defaults are sized for `gemma3:4b`'s context window.
    pub max_input_items: usize,
    pub temperature: f32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            model: "gemma3:4b".to_string(),
            max_input_items: 200,
            temperature: 0.2,
        }
    }
}

/// Common dependencies a built agent needs.
#[derive(Clone)]
pub struct AgentCtx {
    pub llm: Arc<dyn LlmClient>,
    pub config: AgentConfig,
}

impl AgentCtx {
    pub fn new(llm: Arc<dyn LlmClient>, config: AgentConfig) -> Self {
        Self { llm, config }
    }
}
