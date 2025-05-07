pub mod comparison_without_effect;
pub mod delegatecall_in_loop;

pub use comparison_without_effect::ComparisonWithoutEffectDetector;
pub use delegatecall_in_loop::DelegatecallInLoopDetector;
