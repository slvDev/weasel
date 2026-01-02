use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_in_statement;
use crate::utils::location::loc_to_location;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NftHardForkDetector;

impl Detector for NftHardForkDetector {
    fn id(&self) -> &'static str {
        "nft-hard-fork"
    }

    fn name(&self) -> &str {
        "NFT doesn't handle hard forks"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "When there are hard forks, users often have to go through many hoops to ensure that they \
         control ownership on every fork. Consider adding `require(block.chainid == expectedChainId)` \
         to the tokenURI function, or at least include the chain ID in the URI, so that there is no \
         confusion about which chain is the owner of the NFT."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no chain ID handling
function tokenURI(uint256 tokenId) public view returns (string memory) {
    return string(abi.encodePacked(baseURI, tokenId.toString()));
}

// Good - includes chain ID check or in URI
function tokenURI(uint256 tokenId) public view returns (string memory) {
    require(block.chainid == 1, "Wrong chain");
    return string(abi.encodePacked(baseURI, tokenId.toString()));
}

// Good - includes chain ID in URI
function tokenURI(uint256 tokenId) public view returns (string memory) {
    return string(abi.encodePacked(baseURI, block.chainid.toString(), "/", tokenId.toString()));
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let func_name = func_def.name.as_ref().map(|id| id.name.as_str());

            if !matches!(func_name, Some("tokenURI") | Some("tokenUri")) {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            let chainid_refs = find_in_statement(body, file, self.id(), |expr| {
                Self::is_chainid_reference(expr)
            });

            if !chainid_refs.is_empty() {
                return Vec::new();
            }

            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&func_def.loc, file),
            }
            .into()
        });
    }
}

impl NftHardForkDetector {
    fn is_chainid_reference(expr: &Expression) -> bool {
        match expr {
            Expression::MemberAccess(_, base, member) => {
                if member.name.to_lowercase() == "chainid" {
                    if let Expression::Variable(id) = base.as_ref() {
                        return id.name == "block";
                    }
                }
                false
            }
            Expression::Variable(id) => {
                id.name.to_lowercase().contains("chainid")
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_chainid() {
        let code = r#"
            contract NFT {
                string public baseURI;

                function tokenURI(uint256 tokenId) public view returns (string memory) {
                    return string(abi.encodePacked(baseURI, tokenId));
                }

                function tokenUri(uint256 tokenId) external view returns (string memory) {
                    return baseURI;
                }
            }
        "#;
        let detector = Arc::new(NftHardForkDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 5, "tokenURI without chainid");
        assert_eq!(locations[1].line, 9, "tokenUri without chainid");
    }

    #[test]
    fn test_skips_with_chainid() {
        let code = r#"
            contract NFT {
                string public baseURI;
                uint256 public expectedChainId;

                function transfer(address to, uint256 tokenId) public {
                    // No chainid needed here
                }

                function balanceOf(address owner) public view returns (uint256) {
                    return 0;
                }

                function tokenURI(uint256 tokenId) public view returns (string memory) {
                    require(block.chainid == 1, "Wrong chain");
                    return string(abi.encodePacked(baseURI, tokenId));
                }

                function tokenUri(uint256 tokenId) external view returns (string memory) {
                    return string(abi.encodePacked(baseURI, block.chainid, tokenId));
                }

                function anotherTokenURI(uint256 tokenId) public view returns (string memory) {
                    uint256 chainId = block.chainid;
                    return string(abi.encodePacked(baseURI, chainId, tokenId));
                }

                function withVariable(uint256 tokenId) public view returns (string memory) {
                    require(expectedChainId == 1, "Wrong chain");
                    return baseURI;
                }
            }
        "#;
        let detector = Arc::new(NftHardForkDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }

}
