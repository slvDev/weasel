use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionTy, Loc, Statement};
use std::sync::Arc;

const INITIALISMS: [&str; 12] = [
    "NFT", "ERC", "DAO", "ETH", "BTC", "IPFS", "DeFi", "EVM", "ICO", "DEX", "GAS", "API",
];

#[derive(Debug, Default)]
pub struct InitialismCapitalizationDetector;

impl Detector for InitialismCapitalizationDetector {
    fn id(&self) -> &'static str {
        "initialism-capitalization"
    }

    fn name(&self) -> &str {
        "Style guide: Initialisms should be capitalized"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "According to the Solidity style guide, initialisms such as \"NFT\", \"ERC\", \"ETH\", \
         etc. should be capitalized in variable and function names."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uncapitalized initialisms
ERC20 public erc20Token;
function withdrawEth() public {}
uint256 nftId;

// Good - capitalized initialisms
ERC20 public ERC20Token;
function withdrawETH() public {}
uint256 NFTId;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();

        // Check state variables
        visitor.on_variable(move |var_def, file, _context| {
            if let Some(name) = &var_def.name {
                if Self::contains_uncapitalized_initialism(&name.name) {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(&var_def.loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });

        // Check functions, params, returns, and local variables
        visitor.on_function(move |func_def, file, _context| {
            // Skip modifiers
            if matches!(func_def.ty, FunctionTy::Modifier) {
                return Vec::new();
            }

            let mut findings = Vec::new();

            // Check function name
            if let Some(name) = &func_def.name {
                if Self::contains_uncapitalized_initialism(&name.name) {
                    // Report function signature only
                    let issue_loc =
                        if let Some(Statement::Block { loc: body_loc, .. }) = &func_def.body {
                            Loc::default()
                                .with_start(func_def.loc.start())
                                .with_end(body_loc.start())
                        } else {
                            func_def.loc
                        };

                    findings.push(FindingData {
                        detector_id,
                        location: loc_to_location(&issue_loc, file),
                    });
                }
            }

            // Check parameters
            for (loc, param) in &func_def.params {
                if let Some(param) = param {
                    if let Some(name) = &param.name {
                        if Self::contains_uncapitalized_initialism(&name.name) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                }
            }

            // Check return parameters
            for (loc, param) in &func_def.returns {
                if let Some(param) = param {
                    if let Some(name) = &param.name {
                        if Self::contains_uncapitalized_initialism(&name.name) {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                }
            }

            findings
        });
    }
}

impl InitialismCapitalizationDetector {
    fn contains_uncapitalized_initialism(name: &str) -> bool {
        INITIALISMS.iter().any(|&initialism| {
            let lowercase = initialism.to_lowercase();
            name.to_lowercase().contains(&lowercase) && !name.contains(initialism)
        })
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
                ERC20 public erc20Token;                    // Line 5 - state var
                function withdrawEth() public {}            // Line 6 - function name
                function transfer(uint256 nftId) public {}  // Line 7 - param
            }
        "#;
        let detector = Arc::new(InitialismCapitalizationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 issues");
        assert_eq!(locations[0].line, 5, "erc20Token state var");
        assert_eq!(locations[1].line, 6, "withdrawEth function");
        assert_eq!(locations[2].line, 7, "nftId param");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                ERC20 public ERC20Token;                    // Correct - ERC capitalized
                function withdrawETH() public {}            // Correct - ETH capitalized
                function transfer(uint256 NFTId) public {}  // Correct - NFT capitalized
                uint256 public amount;                      // No initialism
            }
        "#;
        let detector = Arc::new(InitialismCapitalizationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
