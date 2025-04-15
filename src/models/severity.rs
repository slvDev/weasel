use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Gas,
    NC,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Gas => write!(f, "Gas"),
            Severity::NC => write!(f, "NC"),
        }
    }
}

impl Severity {
    pub fn as_value(&self) -> u8 {
        match self {
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Gas => 1,
            Severity::NC => 0,
        }
    }
}
