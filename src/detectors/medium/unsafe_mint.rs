use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeMintDetector;

impl Detector for UnsafeMintDetector {
    fn id(&self) -> &'static str {
        "unsafe-mint"
    }

    fn name(&self) -> &str {
        "_safeMint() should be used rather than _mint() wherever possible"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "_mint() is discouraged in favor of _safeMint() which ensures that the recipient is either an EOA \
        or implements IERC721Receiver. Both OpenZeppelin and Solmate have versions of this function \
        so that NFTs aren't lost if they're minted to contracts that cannot transfer them back out. \
        Be careful to respect the CEI pattern or add a re-entrancy guard as _safeMint adds a callback check."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - NFT can be lost if minted to contract:
_mint(to, tokenId);

// Good - checks if recipient can handle NFTs:
_safeMint(to, tokenId);

// Note: Be aware of reentrancy when using _safeMint
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let mut findings = Vec::new();
            
            // Define predicate to find _mint() calls with 2+ args
            let mut is_mint_call = |expr: &Expression, _: &_| -> Option<Loc> {
                if let Expression::FunctionCall(loc, func_expr, args) = expr {
                    // _mint with at least 2 args (to, tokenId/amount)
                    if args.len() >= 2 {
                        if let Expression::Variable(ident) = func_expr.as_ref() {
                            if ident.name == "_mint" {
                                return Some(loc.clone());
                            }
                        }
                    }
                }
                None
            };
            
            // Search function body for _mint calls
            if let Some(body) = &func_def.body {
                ast_utils::find_locations_in_statement(
                    body,
                    file,
                    &mut is_mint_call,
                    &mut findings,
                );
            }

            // Convert findings to FindingData
            findings
                .into_iter()
                .map(|location| FindingData {
                    detector_id: self.id(),
                    location,
                })
                .collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_unsafe_mint() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract MyNFT {
                uint256 private _tokenIdCounter;
                
                function mintNFT(address to) public {
                    uint256 tokenId = _tokenIdCounter++;
                    _mint(to, tokenId); // Should detect
                }
                
                function mintAnother(address to) public {
                    _mint(to, 123); // Should detect
                }
                
                function safeMintNFT(address to) public {
                    uint256 tokenId = _tokenIdCounter++;
                    _safeMint(to, tokenId); // Should NOT detect - using safe version
                }
                
                function wrongArgsCount() public {
                    _mint(msg.sender); // Should NOT detect - only 1 arg
                }
            }
        "#;

        let detector = Arc::new(UnsafeMintDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 unsafe _mint calls");
        assert_eq!(locations[0].line, 9, "First detection");
        assert_eq!(locations[1].line, 13, "Second detection");
    }
    
    #[test]
    fn test_erc1155_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract MyMultiToken {
                function mintToken(address to, uint256 id) public {
                    _mint(to, id, 1); // Should detect - 3 args for ERC1155
                }
                
                function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts) public {
                    for (uint i = 0; i < ids.length; i++) {
                        _mint(to, ids[i], amounts[i]); // Should detect
                    }
                }
            }
        "#;

        let detector = Arc::new(UnsafeMintDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect both _mint calls");
        assert_eq!(locations[0].line, 6, "First detection");
        assert_eq!(locations[1].line, 11, "Second detection in loop");
    }
}