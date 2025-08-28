use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeTransferFromDetector;

impl Detector for UnsafeTransferFromDetector {
    fn id(&self) -> &'static str {
        "unsafe-transferfrom"
    }

    fn name(&self) -> &str {
        "Using transferFrom on ERC721 tokens"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "The transferFrom function is used instead of safeTransferFrom and it's discouraged by OpenZeppelin. \
        If the arbitrary address is a contract and is not aware of the incoming ERC721 token, \
        the sent token could be locked. Use safeTransferFrom to ensure the recipient can handle NFTs."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - token can be locked if sent to contract:
nft.transferFrom(from, to, tokenId);

// Good - ensures recipient can handle NFTs:
nft.safeTransferFrom(from, to, tokenId);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // transferFrom with 3 args (from, to, tokenId)
                if args.len() != 3 {
                    return Vec::new();
                }
                
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    if member.name == "transferFrom" {
                        // Check if any arg looks like a tokenId (contains "id" or "token")
                        let has_id_param = args.iter().any(|arg| {
                            if let Expression::Variable(v) = arg {
                                let name_lower = v.name.to_lowercase();
                                name_lower.contains("id") || name_lower.contains("token")
                            } else {
                                false
                            }
                        });
                        
                        if has_id_param {
                            return FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&loc, file),
                            }
                            .into();
                        }
                    }
                }
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
    fn test_unsafe_transferfrom() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NFTTransfer {
                IERC721 public nft;
                
                function transferNFT(address from, address to, uint256 tokenId) public {
                    // Should detect - has tokenId parameter
                    nft.transferFrom(from, to, tokenId);
                }
                
                function transferWithId(address from, address to) public {
                    uint256 id = 123;
                    // Should detect - has id variable
                    nft.transferFrom(from, to, id);
                }
                
                function safeTransfer(address from, address to, uint256 tokenId) public {
                    // Should NOT detect - using safe version
                    nft.safeTransferFrom(from, to, tokenId);
                }
                
                function transferERC20(address from, address to, uint256 amount) public {
                    // Should NOT detect - no id-like parameter
                    token.transferFrom(from, to, amount);
                }
                
                function wrongArgCount(address to) public {
                    // Should NOT detect - wrong number of args
                    something.transferFrom(to);
                }
            }
        "#;

        let detector = Arc::new(UnsafeTransferFromDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 unsafe transferFrom calls");
        assert_eq!(locations[0].line, 9, "First detection with tokenId");
        assert_eq!(locations[1].line, 15, "Second detection with id variable");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function transferFrom(address from, address to, uint256 tokenId) public {
                    // Function definition, not a call - should NOT detect
                }
                
                function test() public {
                    // Should NOT detect - no id-like parameters
                    token.transferFrom(sender, recipient, amount);
                    token.transferFrom(from, to, value);
                    
                    // Should NOT detect - using safe version
                    nft.safeTransferFrom(from, to, tokenId);
                }
            }
        "#;

        let detector = Arc::new(UnsafeTransferFromDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}