use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::FindingData;
use std::sync::Arc;

const MAX_LINE_LENGTH: usize = 120;

#[derive(Debug, Default)]
pub struct LineLengthDetector;

impl Detector for LineLengthDetector {
    fn id(&self) -> &'static str {
        "line-length"
    }

    fn name(&self) -> &str {
        "Lines are too long"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Lines should not exceed 120 characters. While the traditional limit is 80 characters, \
         modern screens allow more. At 1920px (common full HD), GitHub displays 120 characters \
         without horizontal scrolling."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 public veryLongVariableNameThatExceedsTheMaximumAllowedLineLengthAndMakesCodeHarderToReadOnGitHubBecauseItRequiresHorizontalScrolling;

// Good
uint256 public reasonableVariableName;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |_source_unit, file, _context| {
            let mut findings = Vec::new();

            for (line_num, line) in file.content.lines().enumerate() {
                if line.len() >= MAX_LINE_LENGTH {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: Location {
                            file: file.path.to_string_lossy().to_string(),
                            line: line_num + 1,
                            column: Some(MAX_LINE_LENGTH),
                            line_end: None,
                            column_end: None,
                            snippet: None,
                        },
                    });
                }
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
    fn test_detects_long_lines() {
        let long_line = "a".repeat(121);
        let code = format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {{
    // {}
    uint256 x;
    // {}
}}
"#,
            long_line, long_line
        );
        let detector = Arc::new(LineLengthDetector::default());
        let locations = run_detector_on_code(detector, &code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 5, "first long line");
        assert_eq!(locations[1].line, 7, "second long line");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    uint256 public value;
    function foo() external {}
}
"#;
        let detector = Arc::new(LineLengthDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
