//! Job signature verification and attestation.
//!
//! This module is part of the core security boundary of the Forge platform.
//! All jobs must be verified before any execution is attempted.

use crate::{error::Result, job::SignedJob};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verifies a `SignedJob` using the control plane's public key.
///
/// This must succeed before the job is considered for execution.
pub fn verify_signed_job(job: &SignedJob, public_key: &VerifyingKey) -> Result<()> {
    // Serialize the job payload exactly as it was signed on the control plane side.
    let payload =
        serde_json::to_vec(&job.job).map_err(|e| crate::AgentError::Internal(e.into()))?;

    let signature = Signature::from_slice(&job.signature)
        .map_err(|_| crate::AgentError::SignatureVerification)?;

    public_key
        .verify_strict(&payload, &signature)
        .map_err(|_| crate::AgentError::SignatureVerification)?;

    Ok(())
}

/// Performs local attestation of the execution environment.
///
/// In production this will include measurements of the agent binary,
/// kernel, and optional hardware-backed attestation (TPM, SEV-SNP, etc.).
pub fn attest_execution_environment() -> Result<()> {
    // Current implementation: we treat the agent binary + its configuration
    // as the root of trust. Real remote attestation will be added later.
    Ok(())
}

/// High-level function that runs the full verification pipeline for a job.
pub fn verify_and_attest_job(job: &SignedJob, public_key: &VerifyingKey) -> Result<()> {
    verify_signed_job(job, public_key)?;
    attest_execution_environment()?;
    Ok(())
}
