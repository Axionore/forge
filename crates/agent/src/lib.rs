//! Forge Agent library
//!
//! Core logic for the secure execution agent that runs on every managed node.
//!
//! This is the primary security boundary of the Forge platform.

pub mod build;
pub mod config;
pub mod error;
pub mod execution;
pub mod health;
pub mod identity;
pub mod job;
pub mod receiver;
pub mod verification;
pub mod wireguard;

pub use error::AgentError;
