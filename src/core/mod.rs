// core/mod.rs
// Exports core functionality modules

pub mod context;
pub mod engine;
pub mod registry;
pub mod visitor;

// For the MVP
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
