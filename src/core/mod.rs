pub mod context;
pub mod engine;
pub mod registry;
pub mod visitor;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
