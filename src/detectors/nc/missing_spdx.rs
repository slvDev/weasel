use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::FindingData;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MissingSpdxDetector;

impl Detector for MissingSpdxDetector {
    fn id(&self) -> &'static str {
        "missing-spdx"
    }

    fn name(&self) -> &str {
        "File's first line is not an SPDX Identifier"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Solidity files should start with an SPDX license identifier comment on the first line."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
pragma solidity ^0.8.0;

// Good
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |_source_unit, file, _context| {
            let first_line = file.content.lines().next().unwrap_or("");

            if !first_line.contains("SPDX") {
                return FindingData {
                    detector_id: self.id(),
                    location: Location {
                        file: file.path.to_string_lossy().to_string(),
                        line: 1,
                        column: Some(1),
                        line_end: None,
                        column_end: None,
                        snippet: None,
                    },
                }
                .into();
            }

            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_spdx() {
        let code = r#"pragma solidity ^0.8.0;

contract Test {
    uint256 value;
}
"#;
        let detector = Arc::new(MissingSpdxDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 1, "missing SPDX");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    uint256 value;
}
"#;
        let detector = Arc::new(MissingSpdxDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
