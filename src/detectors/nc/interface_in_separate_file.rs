use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InterfaceInSeparateFileDetector;

impl Detector for InterfaceInSeparateFileDetector {
    fn id(&self) -> &'static str {
        "interface-separate-file"
    }

    fn name(&self) -> &str {
        "Interfaces should be in separate files"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Interfaces should be defined in separate files matching their name for better \
         reusability and to avoid duplication when imported elsewhere."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - IToken defined in Token.sol
// File: Token.sol
interface IToken { ... }
contract Token is IToken { ... }

// Good - IToken in its own file
// File: IToken.sol
interface IToken { ... }

// File: Token.sol
import "./IToken.sol";
contract Token is IToken { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            if !matches!(contract_def.ty, ContractTy::Interface(_)) {
                return Vec::new();
            }

            let Some(name) = &contract_def.name else {
                return Vec::new();
            };

            let file_stem = file
                .path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            if !file_stem.contains(&name.name) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&contract_def.loc, file),
                }
                .into();
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
    fn test_detects_interface_in_wrong_file() {
        let code = r#"
            interface IToken {
                function transfer(address to, uint256 amount) external;
            }

            contract Token {
                // implementation
            }
        "#;
        // File name doesn't contain "IToken"
        let detector = Arc::new(InterfaceInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "Token.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "IToken in Token.sol");
    }

    #[test]
    fn test_skips_interface_in_correct_file() {
        let code = r#"
            interface IToken {
                function transfer(address to, uint256 amount) external;
            }
        "#;
        // File name contains "IToken"
        let detector = Arc::new(InterfaceInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "IToken.sol");
        assert_eq!(locations.len(), 0);

        // Also works for interfaces.sol containing multiple
        let code2 = r#"
            interface IERC20 {
                function balanceOf(address) external view returns (uint256);
            }
        "#;
        let detector2 = Arc::new(InterfaceInSeparateFileDetector::default());
        let locations2 = run_detector_on_code(detector2, code2, "IERC20.sol");
        assert_eq!(locations2.len(), 0);
    }
}
