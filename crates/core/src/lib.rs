//! Forge Core Domain Models
//!
//! Shared types between the control plane (services/api) and agents.
//! This crate must remain lightweight and free of heavy framework dependencies.

pub mod deployment;
pub mod spec;
pub mod supplychain;

pub use deployment::*;
pub use spec::*;
pub use supplychain::*;
