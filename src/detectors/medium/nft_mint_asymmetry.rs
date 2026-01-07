use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NftMintAsymmetryDetector;

impl Detector for NftMintAsymmetryDetector {
    fn id(&self) -> &'static str {
        "nft-mint-asymmetry"
    }

    fn name(&self) -> &str {
        "NFT contract implements _mint()/_safeMint(), but not both"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "If one of the functions is implemented, the other should be as well. \
        The _mint() variant is supposed to skip onERC721Received() checks, whereas _safeMint() does not. \
        Not having both points to a possible issue with spec-compatibility."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - only implements one function:
contract MyNFT {
    function _mint(address to, uint256 tokenId) internal {
        // Custom logic
    }
    // Missing _safeMint
}

// Good - implements both:
contract MyNFT {
    function _mint(address to, uint256 tokenId) internal {
        // Custom logic
    }
    
    function _safeMint(address to, uint256 tokenId) internal {
        _mint(to, tokenId);
        // Check onERC721Received
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract, file, context| {
            if let Some(name) = &contract.name {
                let contract_name = &name.name;
                let qualified_name = context.get_qualified_name_for_contract(contract_name);

                if let Some(contract_info) = context.get_contract(&qualified_name) {
                    let has_mint = contract_info.function_definitions.iter().any(|f| f.name == "_mint");
                    let has_safemint = contract_info.function_definitions.iter().any(|f| f.name == "_safeMint");

                    // Check if only one exists (asymmetry)
                    if has_mint != has_safemint {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&name.loc, file),
                        }
                        .into();
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
    fn test_nft_mint_asymmetry() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract BadNFT {
                // Only implements _mint, not _safeMint
                function _mint(address to, uint256 tokenId) internal {
                    // Custom logic
                }
            }
            
            contract BadNFT2 {
                // Only implements _safeMint, not _mint
                function _safeMint(address to, uint256 tokenId) internal {
                    // Custom logic
                }
            }
            
            contract GoodNFT {
                // Implements both
                function _mint(address to, uint256 tokenId) internal {
                    // Custom logic
                }
                
                function _safeMint(address to, uint256 tokenId) internal {
                    _mint(to, tokenId);
                }
            }
            
            contract NoMintNFT {
                // Neither function - fine
                function customMint(address to, uint256 tokenId) internal {
                    // Custom logic
                }
            }
        "#;

        let detector = Arc::new(NftMintAsymmetryDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 asymmetric implementations");
        assert_eq!(locations[0].line, 4, "BadNFT contract");
        assert_eq!(locations[1].line, 11, "BadNFT2 contract");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                // Both functions implemented - OK
                function _mint(address to, uint256 amount) internal {
                    // Some logic
                }
                
                function _safeMint(address to, uint256 amount) internal {
                    // Some logic
                }
            }
            
            contract Test2 {
                // Different named functions - OK
                function transfer(address to, uint256 amount) public {
                    // Some logic
                }
                
                function safeTransfer(address to, uint256 amount) public {
                    // Some logic
                }
            }
        "#;

        let detector = Arc::new(NftMintAsymmetryDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}