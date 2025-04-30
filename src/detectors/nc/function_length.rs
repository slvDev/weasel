use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::{loc_to_location, offset_to_line_col};
use solang_parser::pt::{FunctionTy, Statement};
use std::sync::{Arc, Mutex};

const MAX_FUNCTION_LINES: usize = 30;

#[derive(Debug, Default)]
pub struct FunctionLengthDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for FunctionLengthDetector {
    fn id(&self) -> &str {
        "function-length"
    }

    fn name(&self) -> &str {
        "Function Too Long"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Functions should ideally be kept concise (e.g., under 30 lines) to improve readability and maintainability. Consider breaking down long functions into smaller, more focused ones."
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

        visitor.on_function(move |func_def, file| {
            if func_def.body.is_none()
                || matches!(
                    func_def.ty,
                    FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive
                )
            {
                return;
            }

            if let Some(Statement::Block { loc, .. }) = &func_def.body {
                let (start_line, _) = offset_to_line_col(loc.start(), &file.line_starts);
                let (end_line, _) = offset_to_line_col(loc.end(), &file.line_starts);

                let line_count = end_line.saturating_sub(start_line);

                if line_count > MAX_FUNCTION_LINES {
                    detector_arc.add_location(loc_to_location(&func_def.loc, file));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_function_length_detector() {
        let long_body = (1..=MAX_FUNCTION_LINES + 5)
            .map(|i| format!("uint var{}; // line {}", i, i))
            .collect::<Vec<_>>()
            .join("\n        ");
        let ok_body = (1..=MAX_FUNCTION_LINES - 1)
            .map(|i| format!("uint var{};", i))
            .collect::<Vec<_>>()
            .join("\n        ");

        let code = format!(
            r#"
            pragma solidity ^0.8.0;

            interface ITest {{ function externalFunc(uint x); }}

            contract Test {{
                constructor() {{ // Negative
                     uint x = 1;
                }}

                // Function slightly below limit
                function okLength() public pure {{ 
                    {}
                }}

                // Function just over limit
                function longFunction() public pure {{
                    {}
                }}

                fallback() external payable {{}} // Negative
                receive() external payable {{}} // Negative
            }}
            // File-level function too long
             function fileLevelLong() public pure {{
                  {}
             }}
        "#,
            ok_body, long_body, long_body
        );

        let detector = Arc::new(FunctionLengthDetector::default());
        let locations = run_detector_on_code(detector, &code, "long_func.sol");

        assert_eq!(
            locations.len(),
            2,
            "Should detect longFunction and fileLevelLong"
        );
        let loc1_snippet = locations[0].snippet.as_deref().unwrap_or("");
        let loc2_snippet = locations[1].snippet.as_deref().unwrap_or("");
        assert!(
            loc1_snippet.contains("longFunction"),
            "Did not find longFunction"
        );
        assert!(
            loc2_snippet.contains("fileLevelLong"),
            "Did not find fileLevelLong"
        );
    }
}
