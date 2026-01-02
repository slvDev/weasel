use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{PragmaDirective, SourceUnitPart, VersionComparator, VersionOp};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnspecificPragmaDetector;

impl Detector for UnspecificPragmaDetector {
    fn id(&self) -> &'static str {
        "unspecific-pragma"
    }

    fn name(&self) -> &str {
        "Unspecific compiler version pragma"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Using floating or range pragma versions (^, >, >=, ~) can lead to unexpected behavior \
         if the contract is compiled with a different version than intended. Consider locking \
         the pragma to a specific version."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - floating version
pragma solidity ^0.8.0;
pragma solidity >=0.8.0;

// Good - specific version
pragma solidity 0.8.19;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut findings = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::PragmaDirective(pragma) = part {
                    if let PragmaDirective::Version(loc, ident, version_req) = pragma.as_ref() {
                        if ident.name == "solidity" && Self::is_unspecific(version_req) {
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                }
            }

            findings
        });
    }
}

impl UnspecificPragmaDetector {
    fn is_unspecific(version_req: &[VersionComparator]) -> bool {
        for comp in version_req {
            match comp {
                // Plain version like "0.8.19" is specific
                VersionComparator::Plain { .. } => {}
                VersionComparator::Operator { op, .. } => {
                    match op {
                        // Exact version "=0.8.19" is specific
                        VersionOp::Exact => {}
                        // These are all unspecific/floating
                        VersionOp::Caret
                        | VersionOp::Tilde
                        | VersionOp::Greater
                        | VersionOp::GreaterEq
                        | VersionOp::Less
                        | VersionOp::LessEq => return true,
                        _ => {}
                    }
                }
                // Range "0.8.0 - 0.8.20" is unspecific
                VersionComparator::Range { .. } => return true,
                // Or conditions - check recursively
                VersionComparator::Or { left, right, .. } => {
                    if Self::is_unspecific(&[*left.clone()])
                        || Self::is_unspecific(&[*right.clone()])
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
    fn test_detects_unspecific_pragma() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test1 {}
        "#;
        let detector = Arc::new(UnspecificPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "^0.8.0 floating");

        let code = r#"
            pragma solidity >=0.8.0;
            contract Test2 {}
        "#;
        let detector = Arc::new(UnspecificPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, ">=0.8.0 range");

        let code = r#"
            pragma solidity >0.8.0;
            contract Test3 {}
        "#;
        let detector = Arc::new(UnspecificPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, ">0.8.0 range");

        let code = r#"
            pragma solidity >=0.8.0 <0.9.0;
            contract Test4 {}
        "#;
        let detector = Arc::new(UnspecificPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, ">=0.8.0 <0.9.0 range");
    }

    #[test]
    fn test_skips_specific_pragma() {
        let code = r#"
            pragma solidity 0.8.19;
            contract Test {}
        "#;
        let detector = Arc::new(UnspecificPragmaDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
