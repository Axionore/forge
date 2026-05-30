//! Agent error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("failed to connect to control plane: {0}")]
    Connection(String),

    #[error("job signature verification failed")]
    SignatureVerification,

    #[error("job attestation failed: {0}")]
    Attestation(String),

    #[error("unsupported job type: {0}")]
    UnsupportedJobType(String),

    #[cfg(feature = "docker")]
    #[error("docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AgentError>;
