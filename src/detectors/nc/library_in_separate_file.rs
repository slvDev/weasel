use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LibraryInSeparateFileDetector;

impl Detector for LibraryInSeparateFileDetector {
    fn id(&self) -> &'static str {
        "library-in-separate-file"
    }

    fn name(&self) -> &str {
        "Library declarations should be in separate files"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Libraries should be declared in a separate file and not in the same file where other \
         contracts/interfaces are declared. This helps in maintaining a clean and organized codebase."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - library and contract in same file
library MathLib { ... }
contract Calculator { ... }

// Good - separate files
// MathLib.sol
library MathLib { ... }

// Calculator.sol
import "./MathLib.sol";
contract Calculator { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut library_locs = Vec::new();
            let mut other_locs = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    let loc = if let Some(name) = &def.name {
                        Loc::File(0, def.loc.start(), name.loc.end())
                    } else {
                        def.loc.clone()
                    };

                    match &def.ty {
                        ContractTy::Library(_) => library_locs.push(loc),
                        ContractTy::Abstract(_)
                        | ContractTy::Interface(_)
                        | ContractTy::Contract(_) => other_locs.push(loc),
                    }
                }
            }

            // Only flag if both libraries and other contracts exist in same file
            if library_locs.is_empty() || other_locs.is_empty() {
                return Vec::new();
            }

            // Report all libraries and other contracts
            let mut findings = Vec::new();
            for loc in library_locs.iter().chain(other_locs.iter()) {
                findings.push(FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(loc, file),
                });
            }

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            library TestLibrary {                    // Line 4 - library
                function add(uint a, uint b) internal pure returns (uint) {
                    return a + b;
                }
            }

            contract TestContract {                  // Line 10 - contract in same file
                function test() public {}
            }
        "#;
        let detector = Arc::new(LibraryInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 4, "library TestLibrary");
        assert_eq!(locations[1].line, 10, "contract TestContract");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            // Only library - OK
            library MathLib {
                function add(uint a, uint b) internal pure returns (uint) {
                    return a + b;
                }
            }
        "#;
        let detector = Arc::new(LibraryInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
