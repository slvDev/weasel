pub mod finding;
pub mod report;
pub mod scope;
pub mod severity;

pub use finding::{Finding, FindingData, Location};
pub use report::Report;
pub use scope::{
    ContractInfo, ContractType, EnumInfo, ErrorInfo, ErrorParameter, EventInfo, EventParameter,
    ImportInfo, ScopeFiles, SolidityFile,
};
pub use severity::Severity;
