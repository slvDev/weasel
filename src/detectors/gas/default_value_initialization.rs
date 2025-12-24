use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractPart, Expression, Loc, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DefaultValueInitializationDetector;

impl Detector for DefaultValueInitializationDetector {
    fn id(&self) -> &'static str {
        "default-value-initialization"
    }

    fn name(&self) -> &str {
        "Don't initialize state variables with default value"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "If a state variable is not set/initialized, it is assumed to have the default value \
        (0 for uint, false for bool, address(0) for address). Explicitly initializing it with \
        its default value is an anti-pattern and wastes gas (~3 gas per instance). \
        Consider removing explicit initializations for default values."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - explicit default initialization
uint256 public counter = 0;
bool public paused = false;
address public owner = address(0);

// Good - implicit default initialization
uint256 public counter;
bool public paused;
address public owner;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::VariableDefinition(var_def) = part {
                    if let Some(init_expr) = &var_def.initializer {
                        if let Some(loc) = Self::is_default_value(init_expr) {
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&loc, file),
                            });
                        }
                    }
                }
            }

            findings
        });
    }
}

impl DefaultValueInitializationDetector {
    fn is_default_value(expr: &Expression) -> Option<Loc> {
        match expr {
            // uint/int = 0
            Expression::NumberLiteral(loc, value, _, _) => {
                if value == "0" {
                    return Some(*loc);
                }
            }
            // bool = false
            Expression::BoolLiteral(loc, value) => {
                if !value {
                    return Some(*loc);
                }
            }
            // address = address(0)
            Expression::FunctionCall(loc, func_expr, args) => {
                if let Expression::Type(_, Type::Address | Type::AddressPayable) = func_expr.as_ref() {
                    if let Some(Expression::NumberLiteral(_, value, _, _)) = args.first() {
                        if value == "0" {
                            return Some(*loc);
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_default_initialization() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public counter = 0;
                int256 public value = 0;
                bool public paused = false;
                address public owner = address(0);
            }
        "#;

        let detector = Arc::new(DefaultValueInitializationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 5, "counter = 0");
        assert_eq!(locations[1].line, 6, "value = 0");
        assert_eq!(locations[2].line, 7, "paused = false");
        assert_eq!(locations[3].line, 8, "owner = address(0)");
    }

    #[test]
    fn test_skips_non_default_values() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public counter = 1;
                uint256 public maxSupply = 10000;
                bool public paused = true;
                address public owner = msg.sender;
                address public treasury = 0x1234567890123456789012345678901234567890;
            }
        "#;

        let detector = Arc::new(DefaultValueInitializationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
