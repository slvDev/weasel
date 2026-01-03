use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement, Type, VariableAttribute};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ZeroInitializationDetector;

impl Detector for ZeroInitializationDetector {
    fn id(&self) -> &'static str {
        "zero-initialization"
    }

    fn name(&self) -> &str {
        "Variables need not be initialized to zero"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "The default value for variables is zero, so initializing them to zero is superfluous."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 x = 0;
address a = address(0);

// Good
uint256 x;
address a;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = Arc::clone(&self);

        // State variables
        visitor.on_variable(move |var_def, file, _context| {
            let is_constant = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Constant(_)));

            if is_constant {
                return Vec::new();
            }

            if let Some(init) = &var_def.initializer {
                if Self::is_zero_value(init) {
                    return FindingData {
                        detector_id: self_clone.id(),
                        location: loc_to_location(&var_def.loc, file),
                    }
                    .into();
                }
            }

            Vec::new()
        });

        // Local variables
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::VariableDefinition(loc, _, Some(init)) = stmt {
                if Self::is_zero_value(init) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });
    }
}

impl ZeroInitializationDetector {
    fn is_zero_value(expr: &Expression) -> bool {
        match expr {
            Expression::NumberLiteral(_, val, _, _) => val == "0",

            Expression::HexNumberLiteral(_, val, _) => {
                let hex = val.strip_prefix("0x").unwrap_or(val);
                hex.chars().all(|c| c == '0')
            }

            Expression::FunctionCall(_, func, args) => {
                if let Expression::Type(_, Type::Address | Type::AddressPayable) = func.as_ref() {
                    if let Some(arg) = args.first() {
                        return Self::is_zero_value(arg);
                    }
                }
                false
            }

            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_zero_initialization() {
        let code = r#"
            contract Test {
                uint256 x = 0;
                address a = address(0);
                bytes32 b = 0x00;

                function foo() public {
                    uint256 local = 0;
                    address localAddr = address(0);
                }
            }
        "#;
        let detector = Arc::new(ZeroInitializationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 3, "state uint256 x = 0");
        assert_eq!(locations[1].line, 4, "state address a = address(0)");
        assert_eq!(locations[2].line, 5, "state bytes32 b = 0x00");
        assert_eq!(locations[3].line, 8, "local uint256 = 0");
        assert_eq!(locations[4].line, 9, "local address = address(0)");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 x;
                address a;
                uint256 constant ZERO = 0;
                uint256 y = 1;
                address b = msg.sender;
            }
        "#;
        let detector = Arc::new(ZeroInitializationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
