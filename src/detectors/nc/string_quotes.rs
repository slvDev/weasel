use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::FindingData;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct StringQuotesDetector;

impl Detector for StringQuotesDetector {
    fn id(&self) -> &'static str {
        "string-quotes"
    }

    fn name(&self) -> &str {
        "Import statements should use double quotes"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "According to the Solidity Style Guide, strings should use double quotes instead of \
         single quotes. See: https://docs.soliditylang.org/en/latest/style-guide.html#other-recommendations"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
import './Base.sol';

// Good
import "./Base.sol";
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |_source_unit, file, _context| {
            let mut findings = Vec::new();

            for (line_num, line) in file.content.lines().enumerate() {
                let trimmed = line.trim_start();

                // Stop when we hit contract/interface/library definitions
                if trimmed.starts_with("contract ")
                    || trimmed.starts_with("interface ")
                    || trimmed.starts_with("library ")
                    || trimmed.starts_with("abstract ")
                    || trimmed.starts_with("function ")
                {
                    break;
                }

                // Check import lines for single quotes
                if trimmed.starts_with("import") && line.contains('\'') {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_single_quotes() {
        let code = r#"
            import './Base.sol';
            import {Foo} from 'lib/Foo.sol';

            contract Test {
                string name = 'Hello';
            }
        "#;
        let detector = Arc::new(StringQuotesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 2, "first import");
        assert_eq!(locations[1].line, 3, "second import");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            import "./Base.sol";
            import {Foo} from "lib/Foo.sol";

            contract Test {
                string name = "Hello";
            }
        "#;
        let detector = Arc::new(StringQuotesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
