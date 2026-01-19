use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MultipleLibrariesDetector;

impl Detector for MultipleLibrariesDetector {
    fn id(&self) -> &'static str {
        "multiple-libraries"
    }

    fn name(&self) -> &str {
        "Multiple libraries declared in single file"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Declaring multiple libraries within a single file can make code more difficult to \
         understand and maintain. It is recommended to declare each library in its own file."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - multiple libraries in one file
library MathLib { ... }
library StringLib { ... }

// Good - separate files
// MathLib.sol
library MathLib { ... }

// StringLib.sol
library StringLib { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut library_locs = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    if let ContractTy::Library(_) = &def.ty {
                        let loc = if let Some(name) = &def.name {
                            Loc::File(0, def.loc.start(), name.loc.end())
                        } else {
                            def.loc.clone()
                        };
                        library_locs.push(loc);
                    }
                }
            }

            // Only flag if more than one library
            if library_locs.len() <= 1 {
                return Vec::new();
            }

            library_locs
                .into_iter()
                .map(|loc| FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&loc, file),
                })
                .collect()
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

            library TestLibraryFirst {                  // Line 4
                function test(uint256 fee) external {}
            }

            library TestLibrarySecond {                 // Line 8
                function test(uint256 fee) public {}
            }
        "#;
        let detector = Arc::new(MultipleLibrariesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 4, "TestLibraryFirst");
        assert_eq!(locations[1].line, 8, "TestLibrarySecond");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            // Single library - OK
            library MathLib {
                function add(uint256 a, uint256 b) external pure returns (uint256) {
                    return a + b;
                }
            }

            // Contracts and interfaces don't count
            contract Token {}
            interface IToken {}
            abstract contract Base {}
        "#;
        let detector = Arc::new(MultipleLibrariesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
