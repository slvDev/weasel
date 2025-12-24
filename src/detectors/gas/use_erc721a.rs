use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Import, ImportPath, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UseErc721aDetector;

impl Detector for UseErc721aDetector {
    fn id(&self) -> &'static str {
        "use-erc721a"
    }

    fn name(&self) -> &str {
        "Use ERC721A instead of ERC721"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "ERC721A is an improvement standard for ERC721 tokens. It was proposed by the Azuki team \
        and used for developing their NFT collection. Compared with ERC721, ERC721A is a more \
        gas-efficient standard to mint a lot of NFTs simultaneously. It allows developers to mint \
        multiple NFTs at the same gas price. Reference: https://nextrope.com/erc721-vs-erc721a-2/"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses standard ERC721
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

// Good - uses gas-efficient ERC721A
import "erc721a/contracts/ERC721A.sol";
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit_part(move |part, file, _context| {
            if let SourceUnitPart::ImportDirective(import) = part {
                let (path_literal, loc) = match import {
                    Import::Plain(literal, loc) => (Some(literal), loc),
                    Import::GlobalSymbol(literal, _, loc) => (Some(literal), loc),
                    Import::Rename(literal, _, loc) => (Some(literal), loc),
                };

                if let Some(ImportPath::Filename(filepath)) = path_literal {
                    let lower_path = filepath.string.to_lowercase();
                    // Check for OpenZeppelin ERC721 import
                    if lower_path.contains("openzeppelin")
                        && lower_path.ends_with("erc721.sol")
                    {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
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
    fn test_detects_openzeppelin_erc721() {
        let code = r#"
            pragma solidity ^0.8.0;

            import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
            import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";

            contract MyNFT is ERC721 {
                constructor() ERC721("MyNFT", "MNFT") {}
            }
        "#;

        let detector = Arc::new(UseErc721aDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 4, "Should detect ERC721.sol import");
    }

    #[test]
    fn test_skips_other_imports() {
        let code = r#"
            pragma solidity ^0.8.0;

            import "erc721a/contracts/ERC721A.sol";
            import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
            import "@openzeppelin/contracts/access/Ownable.sol";

            contract MyNFT is ERC721A, Ownable {
                constructor() ERC721A("MyNFT", "MNFT") Ownable(msg.sender) {}
            }
        "#;

        let detector = Arc::new(UseErc721aDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
