use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InterfaceNamingDetector;

impl Detector for InterfaceNamingDetector {
    fn id(&self) -> &'static str {
        "interface-naming"
    }

    fn name(&self) -> &str {
        "Interfaces should use `I` prefix"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Interface names should be prefixed with `I` (e.g., `IToken`, `IERC20`) to clearly \
         distinguish them from contracts and improve code readability."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
interface Token { ... }
interface ERC20 { ... }

// Good
interface IToken { ... }
interface IERC20 { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            if !matches!(contract_def.ty, ContractTy::Interface(_)) {
                return Vec::new();
            }

            if let Some(name) = &contract_def.name {
                if !name.name.starts_with('I') || name.name.chars().nth(1).map_or(true, |c| c.is_lowercase()) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(&contract_def.loc, file),
                    }
                    .into();
                }
            }

            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_i_prefix() {
        let code = r#"
            interface Token {
                function transfer(address to, uint256 amount) external;
            }

            interface ERC20 {
                function balanceOf(address account) external view returns (uint256);
            }
        "#;
        let detector = Arc::new(InterfaceNamingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 2, "Token interface");
        assert_eq!(locations[1].line, 6, "ERC20 interface");
    }

    #[test]
    fn test_skips_correct_naming() {
        let code = r#"
            interface IToken {
                function transfer(address to, uint256 amount) external;
            }

            interface IERC20 {
                function balanceOf(address account) external view returns (uint256);
            }

            contract Token {
                // Not an interface, shouldn't be flagged
            }
        "#;
        let detector = Arc::new(InterfaceNamingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
