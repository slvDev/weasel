use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractDefinition, ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InterfacesContractsSameFileDetector;

impl Detector for InterfacesContractsSameFileDetector {
    fn id(&self) -> &'static str {
        "interfaces-contracts-same-file"
    }

    fn name(&self) -> &str {
        "Interfaces and Contracts in the Same File"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Interfaces should be declared in a separate file and not in the same file where the \
         contract resides. This helps in maintaining a clean and organized codebase."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - Interface and contract in same file
interface IToken {
    function transfer(address to, uint256 amount) external;
}

contract Token is IToken {
    function transfer(address to, uint256 amount) external { }
}

// Good - Separate files
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
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut interfaces = Vec::new();
            let mut contracts = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    match &def.ty {
                        ContractTy::Interface(_) => interfaces.push(def),
                        ContractTy::Contract(_) => contracts.push(def),
                        _ => {}
                    }
                }
            }

            // Only flag if both interfaces and contracts exist in same file
            if interfaces.is_empty() || contracts.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();
            for def in interfaces {
                findings.push(FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&declaration_loc(def), file),
                });
            }
            for def in contracts {
                findings.push(FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&declaration_loc(def), file),
                });
            }

            findings
        });
    }
}

/// Get location covering only the contract declaration (e.g., "interface IToken")
fn declaration_loc(def: &ContractDefinition) -> Loc {
    let start = def.loc.start();
    let end = def
        .name
        .as_ref()
        .map(|n| n.loc.end())
        .unwrap_or_else(|| def.loc.end());
    Loc::File(0, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            interface IFirst {                      // Line 4 - interface in same file as contracts
                function first() external;
            }

            interface ISecond {                     // Line 8 - another interface
                function second() external;
            }

            contract FirstContract {                // Line 12 - contract in same file as interfaces
                function first() external {}
            }

            contract SecondContract {               // Line 16 - another contract
                function second() external {}
            }
        "#;

        let detector = Arc::new(InterfacesContractsSameFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 2 interfaces and 2 contracts");
        assert_eq!(locations[0].line, 4, "interface IFirst");
        assert_eq!(locations[1].line, 8, "interface ISecond");
        assert_eq!(locations[2].line, 12, "contract FirstContract");
        assert_eq!(locations[3].line, 16, "contract SecondContract");
    }

    #[test]
    fn test_skips_valid_code() {
        // Test 1: Interface-only file
        let code = r#"
            pragma solidity ^0.8.0;

            interface TestInterface {
                function test(uint256 fee) external;
            }
        "#;
        let detector = Arc::new(InterfacesContractsSameFileDetector::default());
        let locations = run_detector_on_code(detector, code, "ITest.sol");
        assert_eq!(locations.len(), 0, "Should not detect interface-only file");

        // Test 2: Contract-only file
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestContract {
                function test(uint256 fee) public {}
            }
        "#;
        let detector = Arc::new(InterfacesContractsSameFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect contract-only file");

        // Test 3: Abstract contracts and libraries (not flagged)
        let code = r#"
            pragma solidity ^0.8.0;

            abstract contract AbstractContract {
                function test(uint256 fee) external virtual;
            }

            library TestLibrary {
                function helper() internal pure {}
            }
        "#;
        let detector = Arc::new(InterfacesContractsSameFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should ignore abstract contracts and libraries");
    }
}
