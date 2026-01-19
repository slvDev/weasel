use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MultipleInterfacesDetector;

impl Detector for MultipleInterfacesDetector {
    fn id(&self) -> &'static str {
        "multiple-interfaces"
    }

    fn name(&self) -> &str {
        "Multiple interfaces declared in single file"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Declaring multiple interfaces within a single file can make code more difficult to \
         understand and maintain. It is recommended to declare each interface in its own file."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - multiple interfaces in one file
interface ITokenA { ... }
interface ITokenB { ... }

// Good - separate files
// ITokenA.sol
interface ITokenA { ... }

// ITokenB.sol
interface ITokenB { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut interface_locs = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    if let ContractTy::Interface(_) = &def.ty {
                        let loc = if let Some(name) = &def.name {
                            Loc::File(0, def.loc.start(), name.loc.end())
                        } else {
                            def.loc.clone()
                        };
                        interface_locs.push(loc);
                    }
                }
            }

            // Only flag if more than one interface
            if interface_locs.len() <= 1 {
                return Vec::new();
            }

            interface_locs
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

            interface ITokenFirst {                     // Line 4
                function transfer() external;
            }

            interface ITokenSecond {                    // Line 8
                function approve() external;
            }
        "#;
        let detector = Arc::new(MultipleInterfacesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 4, "ITokenFirst");
        assert_eq!(locations[1].line, 8, "ITokenSecond");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            // Single interface - OK
            interface IToken {
                function transfer() external;
            }

            // Contracts and libraries don't count
            contract Token {}
            library MathLib {}
            abstract contract Base {}
        "#;
        let detector = Arc::new(MultipleInterfacesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
