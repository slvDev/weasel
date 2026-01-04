use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::FindingData;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TodoLeftDetector;

impl Detector for TodoLeftDetector {
    fn id(&self) -> &'static str {
        "todo-left"
    }

    fn name(&self) -> &str {
        "TODO left in the code"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "TODOs may signal that a feature is missing or not ready for audit. \
         Consider resolving the issue and removing the TODO comment."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
// TODO: implement proper validation
function validate() external {}

// Good
function validate() external {
    require(msg.sender == owner, "Not owner");
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |_source_unit, file, _context| {
            let mut findings = Vec::new();

            for (line_num, line) in file.content.lines().enumerate() {
                if Self::has_todo_comment(line) {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: Location {
                            file: file.path.to_string_lossy().to_string(),
                            line: line_num + 1,
                            column: None,
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

impl TodoLeftDetector {
    fn has_todo_comment(line: &str) -> bool {
        // Find comment start
        let comment_start = if let Some(pos) = line.find("//") {
            Some(pos)
        } else if let Some(pos) = line.find("/*") {
            Some(pos)
        } else if line.trim_start().starts_with('*') {
            // Multi-line comment continuation
            Some(0)
        } else {
            None
        };

        let Some(start) = comment_start else {
            return false;
        };

        // Check if comment part contains "todo" (case-insensitive)
        line[start..].to_lowercase().contains("todo")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_todos() {
        let code = r#"
            contract Test {
                // TODO: implement this
                //todo: also this
                /* TODO: fix this later */
                /**
                 * todo: multiline comment
                 */
                function foo() external {}
            }
        "#;
        let detector = Arc::new(TodoLeftDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 3, "// TODO");
        assert_eq!(locations[1].line, 4, "//todo");
        assert_eq!(locations[2].line, 5, "/* TODO");
        assert_eq!(locations[3].line, 7, "* todo");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                mapping(address => uint256) todoList;
                string name = "TODO";
                function foo() external {}
            }
        "#;
        let detector = Arc::new(TodoLeftDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
