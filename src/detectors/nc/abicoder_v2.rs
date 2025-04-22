use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{PragmaDirective, SourceUnitPart};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct UnnecessaryAbiCoderV2Detector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for UnnecessaryAbiCoderV2Detector {
    fn id(&self) -> &str {
        "unnecessary-abicoder-v2"
    }

    fn name(&self) -> &str {
        "Unnecessary `pragma abicoder v2`"
    }

    fn severity(&self) -> Severity {
        Severity::NC // Could also be considered Gas/Info
    }

    fn description(&self) -> &str {
        "abicoder v2 is enabled by default starting with Solidity 0.8.0. \
        Explicitly enabling it via `pragma abicoder v2;` is redundant for such versions."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        None
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_source_unit_part(move |part, file| {
            // TODO: implement more sophisticated version check
            let is_version_gte_0_8 = match &file.solidity_version {
                Some(version_str) => version_str.contains("0.8") || version_str.contains("0.9"),
                None => false,
            };

            if !is_version_gte_0_8 {
                return;
            }

            if let SourceUnitPart::PragmaDirective(pragma_box) = part {
                let pragma = &**pragma_box;
                if let PragmaDirective::Identifier(loc, Some(ident1), Some(ident2)) = pragma {
                    if ident1.name == "abicoder" && ident2.name == "v2" {
                        detector_arc.add_location(loc_to_location(loc, file));
                    }
                }
            }
        });
    }
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_unnecessary_abicoder_v2_detection() {
        let code = r#"
            pragma solidity ^0.8.10;
            pragma abicoder v2; // Unnecessary
            contract Test1 {}
        "#;
        let detector = Arc::new(UnnecessaryAbiCoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test_detect.sol");
        assert_eq!(locations.len(), 1, "Should detect in >=0.8.0");
        assert_eq!(locations[0].line, 3, "Line number should be 2");
        assert!(locations[0]
            .snippet
            .as_deref()
            .unwrap_or("")
            .contains("pragma abicoder v2"));

        let code = r#"
            pragma solidity ^0.7.0;
            pragma abicoder v2; // Necessary here

            contract Test2 {}
        "#;
        let detector = Arc::new(UnnecessaryAbiCoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test_no_detect_v7.sol");
        assert_eq!(locations.len(), 0, "Should NOT detect in <0.8.0");

        let code = r#"
            pragma solidity >=0.8.0;
            contract Test3 {}
        "#;
        let detector = Arc::new(UnnecessaryAbiCoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test_no_detect_no_pragma.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should NOT detect when pragma is absent"
        );

        let code = r#"
            pragma solidity ^0.8.0;
            pragma experimental ABIEncoderV2; // Different pragma

            contract Test4 {}
        "#;
        let detector = Arc::new(UnnecessaryAbiCoderV2Detector::default());
        let locations = run_detector_on_code(detector, code, "test_no_detect_experimental.sol");
        assert_eq!(locations.len(), 0, "Should NOT detect experimental pragma");
    }
}
