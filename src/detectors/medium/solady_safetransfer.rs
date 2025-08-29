use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SoladySafeTransferDetector;

impl Detector for SoladySafeTransferDetector {
    fn id(&self) -> &'static str {
        "solady-safetransfer"
    }

    fn name(&self) -> &str {
        "Solady's SafeTransferLib does not check for token contract's existence"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "There is a subtle difference between the implementation of solady's SafeTransferLib and OZ's SafeERC20: \
        OZ's SafeERC20 checks if the token is a contract or not, solady's SafeTransferLib does not. \
        https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L10 \
        Note that none of the functions in this library check that a token has code at all! \
        That responsibility is delegated to the caller."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

contract TokenHandler {
    using SafeTransferLib for address;
    
    function transfer(address token, address to, uint256 amount) external {
        // Bad - Solady's SafeTransferLib doesn't check contract existence
        token.safeTransfer(to, amount);
    }
}

// Solution: Either check contract existence manually or use OpenZeppelin's SafeERC20
contract BetterTokenHandler {
    using SafeTransferLib for address;
    
    function transfer(address token, address to, uint256 amount) external {
        require(token.code.length > 0, "Token is not a contract");
        token.safeTransfer(to, amount);
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            // First check if this file has the Solady SafeTransferLib import
            let has_solady = file.imports.iter().any(|import| {
                import.import_path.contains("solady") && 
                import.import_path.contains("SafeTransferLib")
            });
            
            if !has_solady {
                return Vec::new();
            }
            
            if let Some(body) = &func.body {
                // Define predicate to find safeTransfer/safeTransferFrom/safeApprove calls
                let mut is_solady_safe_call = |expr: &Expression, _: &_| -> Option<Loc> {
                    if let Expression::FunctionCall(loc, func_expr, _) = expr {
                        if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                            match member.name.as_str() {
                                "safeTransfer" | "safeTransferFrom" | "safeApprove" => {
                                    return Some(loc.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    None
                };
                
                // Search for Solady safe calls in the function body
                let mut solady_locations = Vec::new();
                ast_utils::find_locations_in_statement(
                    body,
                    file,
                    &mut is_solady_safe_call,
                    &mut solady_locations,
                );
                
                // Convert found locations to findings
                return solady_locations
                    .into_iter()
                    .map(|location| FindingData {
                        detector_id: self.id(),
                        location,
                    })
                    .collect();
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
    fn test_solady_safetransfer() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
            
            contract TokenHandler {
                using SafeTransferLib for address;
                
                function transfer(address token, address to, uint256 amount) external {
                    token.safeTransfer(to, amount); // Should detect
                }
                
                function transferFrom(address token, address from, address to, uint256 amount) external {
                    token.safeTransferFrom(from, to, amount); // Should detect
                }
                
                function approve(address token, address spender, uint256 amount) external {
                    token.safeApprove(spender, amount); // Should detect
                }
                
                function normalTransfer(address token, address to, uint256 amount) external {
                    // Regular transfer - should not detect
                    IERC20(token).transfer(to, amount);
                }
            }
        "#;

        let detector = Arc::new(SoladySafeTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 unsafe Solady calls");
        assert_eq!(locations[0].line, 10, "safeTransfer call");
        assert_eq!(locations[1].line, 14, "safeTransferFrom call");
        assert_eq!(locations[2].line, 18, "safeApprove call");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
            
            contract OZHandler {
                using SafeERC20 for IERC20;
                
                function transfer(IERC20 token, address to, uint256 amount) external {
                    // OpenZeppelin's SafeERC20 - OK
                    token.safeTransfer(to, amount);
                }
            }
            
            contract NoImportHandler {
                // No Solady import - OK
                function transfer(address token, address to, uint256 amount) external {
                    // This would be a different issue (calling non-existent function)
                    // but not this detector's concern
                    safeTransfer(token, to, amount);
                }
            }
        "#;

        let detector = Arc::new(SoladySafeTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}