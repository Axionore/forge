//! Forge Agent library
//!
//! Core logic for the secure execution agent that runs on every managed node.
//!
//! This is the primary security boundary of the Forge platform.

pub mod config;
pub mod error;
pub mod execution;
pub mod health;
pub mod job;
pub mod receiver;
pub mod verification;
pub mod wireguard;
pub mod identity;

pub use error::AgentError;