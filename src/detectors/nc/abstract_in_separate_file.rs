use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractDefinition, ContractTy, Loc, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AbstractInSeparateFileDetector;

impl Detector for AbstractInSeparateFileDetector {
    fn id(&self) -> &'static str {
        "abstract-in-separate-file"
    }

    fn name(&self) -> &str {
        "Abstract contract should be in a separate file"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Abstract contracts should be declared in a separate file, not in the same file where \
        concrete contracts are declared. This helps maintain a clean and organized codebase, \
        improves readability, and makes it easier to manage inheritance hierarchies."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - abstract and concrete in same file
abstract contract Base {
    function foo() external virtual;
}

contract Implementation is Base {
    function foo() external override {}
}

// Good - separate files
// Base.sol
abstract contract Base {
    function foo() external virtual;
}

// Implementation.sol
import "./Base.sol";
contract Implementation is Base {
    function foo() external override {}
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut abstracts = Vec::new();
            let mut contracts = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(def) = part {
                    match &def.ty {
                        ContractTy::Abstract(_) => abstracts.push(def),
                        ContractTy::Contract(_) => contracts.push(def),
                        _ => {}
                    }
                }
            }

            // Only flag if both abstract and concrete contracts exist in same file
            if abstracts.is_empty() || contracts.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();
            for def in abstracts {
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

/// Get location covering only the contract declaration (e.g., "abstract contract Base")
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
    fn test_detects_mixed_abstract_and_contract() {
        let code = r#"
            pragma solidity ^0.8.0;

            abstract contract Base {
                function foo() external virtual;
            }

            contract Implementation is Base {
                function foo() external override {}
            }
        "#;

        let detector = Arc::new(AbstractInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "abstract contract Base");
        assert_eq!(locations[1].line, 8, "contract Implementation");
    }

    #[test]
    fn test_skips_single_type_files() {
        let code = r#"
            pragma solidity ^0.8.0;

            abstract contract Base1 {
                function foo() external virtual;
            }

            abstract contract Base2 {
                function bar() external virtual;
            }
        "#;

        let detector = Arc::new(AbstractInSeparateFileDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
