// core/mod.rs
// Exports core functionality modules

pub mod engine;
pub mod registry;
pub mod visitor;

// pub mod context;

// For the MVP
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
