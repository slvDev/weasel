// detectors/nc/mod.rs
// Exports NC (Non-Critical) detectors

pub mod abi_encode_call;
pub mod array_indices;

pub use abi_encode_call::AbiEncodeCallDetector;
pub use array_indices::ArrayIndicesDetector;
