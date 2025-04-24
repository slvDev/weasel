// detectors/nc/mod.rs
// Exports NC (Non-Critical) detectors

pub mod abi_encode_call;
pub mod abicoder_v2;
pub mod array_indices;
pub mod prefer_require;

pub use abi_encode_call::AbiEncodeCallDetector;
pub use abicoder_v2::UnnecessaryAbiCoderV2Detector;
pub use array_indices::ArrayIndicesDetector;
pub use prefer_require::PreferRequireDetector;
