use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{CatchClause, Expression, FunctionAttribute, FunctionTy, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EmptyBlocksDetector;

impl Detector for EmptyBlocksDetector {
    fn id(&self) -> &'static str {
        "empty-blocks"
    }

    fn name(&self) -> &str {
        "Avoid empty blocks in code"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Empty blocks in code can lead to confusion and the introduction of errors when the \
         code is later modified. They should be removed, or the block should do something \
         useful, such as emitting an event or reverting. For contracts meant to be extended, \
         the contract should be abstract and the function signatures added without any \
         default implementation."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - empty blocks
function doNothing() public {}
if (condition) {} else { doSomething(); }
try token.transfer() {} catch { handleError(); }

// Good - meaningful implementations or abstract
function doSomething() public { emit Action(); }
abstract contract Base { function action() public virtual; }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_function(move |func_def, file, _context| {
            // Skip virtual functions
            if func_def
                .attributes
                .iter()
                .any(|attr| matches!(attr, FunctionAttribute::Virtual(_)))
            {
                return Vec::new();
            }

            if func_def.ty == FunctionTy::Constructor {
                return Vec::new();
            }

            // Check if function body is empty
            if let Some(body) = &func_def.body {
                if let Some(block_loc) = Self::empty_block_loc(body) {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(block_loc, file),
                    }
                    .into();
                }
            }

            Vec::new()
        });

        visitor.on_statement(move |stmt, file, _context| {
            let mut findings = Vec::new();

            match stmt {
                Statement::If(_, _, if_body, else_body) => {
                    // Check empty if block
                    if let Some(block_loc) = Self::empty_block_loc(if_body.as_ref()) {
                        findings.push(FindingData {
                            detector_id,
                            location: loc_to_location(block_loc, file),
                        });
                    }
                    // Check empty else block
                    if let Some(else_stmt) = else_body {
                        if let Some(block_loc) = Self::empty_block_loc(else_stmt.as_ref()) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(block_loc, file),
                            });
                        }
                    }
                }
                Statement::Try(_, expr, returns, catches) => {
                    // Check empty try block (FunctionCallBlock)
                    if let Expression::FunctionCallBlock(_, _, block) = expr {
                        if let Some(block_loc) = Self::empty_block_loc(block) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(block_loc, file),
                            });
                        }
                    }
                    // Check empty returns block
                    if let Some((_, block)) = returns {
                        if let Some(block_loc) = Self::empty_block_loc(block) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(block_loc, file),
                            });
                        }
                    }
                    // Check empty catch blocks
                    for catch in catches {
                        let block = match catch {
                            CatchClause::Simple(_, _, block) => block,
                            CatchClause::Named(_, _, _, block) => block,
                        };
                        if let Some(block_loc) = Self::empty_block_loc(block) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(block_loc, file),
                            });
                        }
                    }
                }
                _ => {}
            }

            findings
        });
    }
}

impl EmptyBlocksDetector {
    /// Returns the location if the statement is an empty block
    fn empty_block_loc(stmt: &Statement) -> Option<&solang_parser::pt::Loc> {
        match stmt {
            Statement::Block { loc, statements, .. } if statements.is_empty() => Some(loc),
            _ => None,
        }
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

            contract Test {
                function emptyFunc() public {}              // Line 5 - empty {}

                function emptyIf() public {
                    if (true) {} else {                     // Line 8 - empty {}
                        doSomething();
                    }
                }

                function emptyElse() public {
                    if (true) {
                        doSomething();
                    } else {}                               // Line 16 - empty {}
                }

                function emptyCatch() external {
                    try this.emptyFunc() {
                        doSomething();
                    } catch {}                              // Line 22 - empty {}
                }

                function emptyTry() external {
                    try this.emptyFunc() {} catch {         // Line 26 - empty {}
                        doSomething();
                    }
                }
            }
        "#;
        let detector = Arc::new(EmptyBlocksDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5, "Should detect 5 empty blocks");
        assert_eq!(locations[0].line, 5, "empty function body");
        assert_eq!(locations[1].line, 8, "empty if block");
        assert_eq!(locations[2].line, 16, "empty else block");
        assert_eq!(locations[3].line, 22, "empty catch block");
        assert_eq!(locations[4].line, 26, "empty try block");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            abstract contract Base {
                function virtualFunc() public virtual;      // No body - abstract
            }

            contract Test is Base {
                constructor() {}                            // Empty constructor - OK

                function virtualFunc() public virtual {}    // Virtual - OK

                function normalFunc() public {
                    doSomething();                          // Has content - OK
                }

                function ifElse() public {
                    if (true) {
                        doSomething();                      // Has content - OK
                    } else {
                        doOther();                          // Has content - OK
                    }
                }

                function tryCatch() external {
                    try this.normalFunc() {
                        doSomething();                      // Has content - OK
                    } catch {
                        handleError();                      // Has content - OK
                    }
                }
            }
        "#;
        let detector = Arc::new(EmptyBlocksDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any empty blocks");
    }
}
