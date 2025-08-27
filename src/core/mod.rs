pub mod c3_linearization;
pub mod context;
pub mod engine;
pub mod finding_collector;
pub mod processor;
pub mod registry;
pub mod visitor;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
