use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ControlStructureStyleDetector;

impl Detector for ControlStructureStyleDetector {
    fn id(&self) -> &'static str {
        "control-structure-style"
    }

    fn name(&self) -> &str {
        "Control structures do not follow the Solidity Style Guide"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Control structures should follow the Solidity Style Guide: space between keyword and \
         parenthesis, space before opening brace. \
         See: https://docs.soliditylang.org/en/latest/style-guide.html#control-structures"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
if(x > 0){
if (x > 0){
for(uint i; i < 10; i++){

// Good
if (x > 0) {
for (uint i; i < 10; i++) {
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            let loc = match stmt {
                Statement::If(loc, _, _, _) => loc,
                Statement::While(loc, _, _) => loc,
                Statement::For(loc, _, _, _, _) => loc,
                _ => return Vec::new(),
            };

            let Loc::File(_, start, end) = loc else {
                return Vec::new();
            };

            let Some(source) = file.content.get(*start..(*end).min(file.content.len())) else {
                return Vec::new();
            };

            let first_line = source.lines().next().unwrap_or("");

            if Self::has_style_violation(first_line) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

impl ControlStructureStyleDetector {
    fn has_style_violation(line: &str) -> bool {
        // No space after keyword: if(, while(, for(
        if line.contains("if(") || line.contains("while(") || line.contains("for(") {
            return true;
        }

        // No space before brace: ){
        if line.contains("){") {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_style_violations() {
        let code = r#"
            contract Test {
                function foo() external {
                    if(x > 0) { 
                        x = 1;
                    }
                    if (x > 0){ 
                        x = 1;
                    }
                    while(true) { break; }
                    for(uint i; i < 10; i++) { }
                }
            }
        "#;
        let detector = Arc::new(ControlStructureStyleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 4, "if( - no space");
        assert_eq!(locations[1].line, 7, "){{ - no space before brace");
        assert_eq!(locations[2].line, 10, "while( - no space");
        assert_eq!(locations[3].line, 11, "for( - no space");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                function foo() external {
                    if (x > 0) { 
                        x = 1;
                    }
                    while (true) { 
                        break;
                    }
                    for (uint i; i < 10; i++) { }
                }
            }
        "#;
        let detector = Arc::new(ControlStructureStyleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
