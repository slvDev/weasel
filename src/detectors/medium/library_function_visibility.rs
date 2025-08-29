use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::{ast_utils, location::loc_to_location};
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractPart, ContractTy, FunctionTy, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LibraryFunctionVisibilityDetector;

impl Detector for LibraryFunctionVisibilityDetector {
    fn id(&self) -> &'static str {
        "library-function-visibility"
    }

    fn name(&self) -> &str {
        "Library function isn't internal or private"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "In a library, using external or public visibility means that we won't be going through \
        the library with a DELEGATECALL but with a CALL. This changes the context and should be done carefully. \
        Library functions should typically be internal to be embedded in the calling contract's bytecode."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses CALL, not DELEGATECALL:
library MyLib {
    function helper() public { }  // Wrong visibility
    function calc() external { }  // Wrong visibility
}

// Good - uses DELEGATECALL:
library MyLib {
    function helper() internal { }
    function calc() private { }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            // Only check libraries
            let is_library = matches!(contract_def.ty, ContractTy::Library(_));
            if !is_library {
                return Vec::new();
            }

            let mut findings = Vec::new();

            // Check all functions in the library
            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    // Skip constructors and virtual functions
                    if matches!(func_def.ty, FunctionTy::Constructor) {
                        continue;
                    }
                    
                    // Check for virtual functions
                    if ast_utils::is_function_virtual(func_def) {
                        continue;
                    }

                    // Check visibility
                    let visibility = ast_utils::get_function_visibility(func_def);

                    // If no visibility specified, default is internal for libraries (which is fine)
                    if let Some(vis) = visibility {
                        if matches!(vis, Visibility::External(_) | Visibility::Public(_)) {
                            // Report at function name location
                            let loc = if let Some(name) = &func_def.name {
                                name.loc
                            } else {
                                func_def.loc_prototype
                            };
                            
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&loc, file),
                            });
                        }
                    }
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
    fn test_library_function_visibility() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            library MathLib {
                // Should detect - public visibility
                function add(uint a, uint b) public pure returns (uint) {
                    return a + b;
                }
                
                // Should detect - external visibility
                function sub(uint a, uint b) external pure returns (uint) {
                    return a - b;
                }
                
                // Should NOT detect - internal visibility
                function mul(uint a, uint b) internal pure returns (uint) {
                    return a * b;
                }
                
                // Should NOT detect - private visibility
                function div(uint a, uint b) private pure returns (uint) {
                    return a / b;
                }
                
                // Should NOT detect - no visibility (defaults to internal)
                function mod(uint a, uint b) pure returns (uint) {
                    return a % b;
                }
            }
        "#;

        let detector = Arc::new(LibraryFunctionVisibilityDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 functions with wrong visibility");
        assert_eq!(locations[0].line, 6, "Detection for public function");
        assert_eq!(locations[1].line, 11, "Detection for external function");
    }

    #[test]
    fn test_not_library() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NotALibrary {
                // Should NOT detect - not a library
                function test() public { }
                function test2() external { }
            }
            
            interface ITest {
                // Should NOT detect - not a library
                function test() external;
            }
        "#;

        let detector = Arc::new(LibraryFunctionVisibilityDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect in non-library contracts");
    }

    #[test]
    fn test_virtual_functions() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            library TestLib {
                // Should NOT detect - virtual function
                function virtualFunc() public virtual returns (uint) {
                    return 1;
                }
                
                // Should detect - non-virtual public
                function regularFunc() public returns (uint) {
                    return 2;
                }
            }
        "#;

        let detector = Arc::new(LibraryFunctionVisibilityDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1, "Should only detect non-virtual public function");
        assert_eq!(locations[0].line, 11, "Detection for regularFunc");
    }
}