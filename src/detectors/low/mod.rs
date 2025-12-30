pub mod curve_calc_token_amount;
pub mod decimals_type;
pub mod deprecated_approve;
pub mod ecrecover_malleability;
pub mod erc20_decimals;
pub mod two_step_ownership_transfer;

pub use curve_calc_token_amount::CurveCalcTokenAmountDetector;
pub use decimals_type::DecimalsTypeDetector;
pub use deprecated_approve::DeprecatedApproveDetector;
pub use ecrecover_malleability::EcrecoverMalleabilityDetector;
pub use erc20_decimals::Erc20DecimalsDetector;
pub use two_step_ownership_transfer::TwoStepOwnershipTransferDetector;
