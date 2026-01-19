use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MultipleAbstractContractsDetector;

impl Detector for MultipleAbstractContractsDetector {
    fn id(&self) -> &'static str {
        "multiple-abstract-contracts"
    }

    fn name(&self) -> &str {
        "Multiple abstract contracts declared in one file"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Declaring multiple abstract contracts in one file can make code more difficult to \
         understand. It is recommended to declare each abstract contract in its own file, \
         following the one abstract contract per file rule."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - multiple abstract contracts in one file
abstract contract Base1 { ... }
abstract contract Base2 { ... }

// Good - separate files
// Base1.sol
abstract contract Base1 { ... }

// Base2.sol
abstract contract Base2 { ... }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut abstract_locs = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    if let ContractTy::Abstract(_) = &def.ty {
                        let loc = if let Some(name) = &def.name {
                            Loc::File(0, def.loc.start(), name.loc.end())
                        } else {
                            def.loc.clone()
                        };
                        abstract_locs.push(loc);
                    }
                }
            }

            // Only flag if more than one abstract contract
            if abstract_locs.len() <= 1 {
                return Vec::new();
            }

            abstract_locs
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

            abstract contract TestContractFirst {       // Line 4
                function test(uint256 fee) external;
            }

            abstract contract TestContractSecond {      // Line 8
                function test(uint256 fee) public;
            }
        "#;
        let detector = Arc::new(MultipleAbstractContractsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 4, "TestContractFirst");
        assert_eq!(locations[1].line, 8, "TestContractSecond");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            // Single abstract contract - OK
            abstract contract OnlyOne {
                function test() external;
            }
        "#;
        let detector = Arc::new(MultipleAbstractContractsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
