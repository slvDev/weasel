use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{PragmaDirective, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedAbiEncoderV2Detector;

impl Detector for DeprecatedAbiEncoderV2Detector {
    fn id(&self) -> &'static str {
        "deprecated-abi-encoder-v2"
    }

    fn name(&self) -> &str {
        "`pragma experimental ABIEncoderV2` is deprecated"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Use `pragma abicoder v2` instead of the deprecated `pragma experimental ABIEncoderV2`. \
         The experimental keyword is no longer needed as of Solidity 0.8.0. See: \
         https://github.com/ethereum/solidity/blob/69411436139acf5dbcfc5828446f18b9fcfee32c/docs/080-breaking-changes.rst#silent-changes-of-the-semantics"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - deprecated pragma
pragma experimental ABIEncoderV2;

contract Test {
    struct Data {
        uint256 value;
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            let mut findings = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::PragmaDirective(pragma) = part {
                    if let PragmaDirective::Identifier(loc, first, second) = pragma.as_ref() {
                        if Self::is_experimental_abi_encoder_v2(first, second) {
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

impl DeprecatedAbiEncoderV2Detector {
    fn is_experimental_abi_encoder_v2(
        first: &Option<solang_parser::pt::Identifier>,
        second: &Option<solang_parser::pt::Identifier>,
    ) -> bool {
        if let (Some(f), Some(s)) = (first, second) {
            f.name.to_lowercase() == "experimental"
                && s.name.to_lowercase() == "abiencoderv2"
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_deprecated_pragma() {
        let code = r#"
            pragma experimental ABIEncoderV2;

            contract Test {
                struct Data {
                    uint256 value;
                }
            }
        "#;
        let detector = Arc::new(DeprecatedAbiEncoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "pragma experimental ABIEncoderV2");
    }

    #[test]
    fn test_skips_modern_pragma() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                struct Data {
                    uint256 value;
                }
            }
        "#;
        let detector = Arc::new(DeprecatedAbiEncoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
