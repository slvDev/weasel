use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractTy, PragmaDirective, SourceUnitPart, VersionComparator, VersionOp};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct FloatingPragmaDetector;

impl Detector for FloatingPragmaDetector {
    fn id(&self) -> &'static str {
        "floating-pragma"
    }

    fn name(&self) -> &str {
        "Non-library/interface files should use fixed compiler versions, not floating ones"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Floating pragmas may lead to unintended vulnerabilities due to different compiler \
         versions. It is recommended to lock the Solidity version in pragma statements for \
         contracts and abstract contracts."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - floating pragma in contract
pragma solidity ^0.8.0;
contract MyContract {}

// Bad - range pragma in contract
pragma solidity >=0.8.0 <0.9.0;
contract MyContract {}

// Good - fixed version for contracts
pragma solidity 0.8.20;
contract MyContract {}

// OK - floating pragma in library/interface (acceptable)
pragma solidity ^0.8.0;
library MyLibrary {}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut floating_pragma_location = None;
            let mut has_contract = false;

            for part in &source_unit.0 {
                match part {
                    SourceUnitPart::PragmaDirective(pragma) => {
                        if let PragmaDirective::Version(loc, ident, version_req) = pragma.as_ref() {
                            if ident.name == "solidity" && Self::is_floating_pragma(version_req) {
                                floating_pragma_location = Some(loc_to_location(loc, file));
                            }
                        }
                    }
                    SourceUnitPart::ContractDefinition(c)
                        if matches!(c.ty, ContractTy::Abstract(_) | ContractTy::Contract(_)) =>
                    {
                        has_contract = true;
                    }
                    _ => {}
                }
            }

            if has_contract {
                if let Some(location) = floating_pragma_location {
                    return FindingData {
                        detector_id: self.id(),
                        location,
                    }
                    .into();
                }
            }

            Vec::new()
        });
    }
}

impl FloatingPragmaDetector {
    fn is_floating_pragma(version_req: &[VersionComparator]) -> bool {
        for comp in version_req {
            match comp {
                VersionComparator::Plain { .. } => {}
                VersionComparator::Operator { op, .. } => match op {
                    VersionOp::Exact => {}
                    VersionOp::Caret
                    | VersionOp::Tilde
                    | VersionOp::Greater
                    | VersionOp::GreaterEq
                    | VersionOp::Less
                    | VersionOp::LessEq => return true,
                    _ => {}
                },
                VersionComparator::Range { .. } => return true,
                VersionComparator::Or { left, right, .. } => {
                    if Self::is_floating_pragma(&[*left.clone()])
                        || Self::is_floating_pragma(&[*right.clone()])
                    {
                        return true;
                    }
                }
            }
        }
        false
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
            contract Test {}
        "#;
        let detector = Arc::new(FloatingPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1, "Should detect 1 issue");
        assert_eq!(locations[0].line, 2, "floating pragma");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity 0.8.20;
            contract Test {}
        "#;
        let detector = Arc::new(FloatingPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect fixed pragma");

        // Library with floating pragma - OK
        let code2 = r#"
            pragma solidity ^0.8.0;
            library MyLib {}
        "#;
        let locations2 = run_detector_on_code(Arc::new(FloatingPragmaDetector::default()), code2, "test.sol");
        assert_eq!(locations2.len(), 0, "Should not detect library");

        // Interface with floating pragma - OK
        let code3 = r#"
            pragma solidity ^0.8.0;
            interface ITest {}
        "#;
        let locations3 = run_detector_on_code(Arc::new(FloatingPragmaDetector::default()), code3, "test.sol");
        assert_eq!(locations3.len(), 0, "Should not detect interface");
    }
}
