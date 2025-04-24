// detectors/nc/mod.rs
// Exports NC (Non-Critical) detectors

pub mod abi_encode_call;
pub mod abicoder_v2;
pub mod array_indices;
pub mod constant_case;
pub mod magic_numbers;
pub mod prefer_concat;
pub mod prefer_require;
pub mod two_step_critical_changes;
pub mod while_true_loop;

pub use abi_encode_call::AbiEncodeCallDetector;
pub use abicoder_v2::UnnecessaryAbiCoderV2Detector;
pub use array_indices::ArrayIndicesDetector;
pub use constant_case::ConstantCaseDetector;
pub use magic_numbers::MagicNumberDetector;
pub use prefer_concat::PreferConcatDetector;
pub use prefer_require::PreferRequireDetector;
pub use two_step_critical_changes::TwoStepCriticalChangesDetector;
pub use while_true_loop::WhileTrueLoopDetector;
