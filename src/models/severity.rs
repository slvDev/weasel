use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Severity {
    High,
    Medium,
    Low,
    Gas,
    #[default]
    NC,
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

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "gas" => Ok(Severity::Gas),
            "nc" => Ok(Severity::NC),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}
