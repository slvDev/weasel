use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DomainSeparatorReplayDetector;

impl Detector for DomainSeparatorReplayDetector {
    fn id(&self) -> &'static str {
        "domain-separator-replay"
    }

    fn name(&self) -> &str {
        "`domainSeparator()` isn't protected against replay attacks in case of a future chain split"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The domain separator should be recalculated if the current `block.chainid` is not the cached chain ID \
         to protect against replay attacks in case of a future chain split. See EIP-2612 security considerations: \
         https://eips.ethereum.org/EIPS/eip-2612#security-considerations. Consider using OpenZeppelin's EIP712 \
         implementation which properly handles chain ID changes: \
         https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - cached domain separator never recalculated
contract Token {
    bytes32 private immutable _DOMAIN_SEPARATOR;

    constructor() {
        _DOMAIN_SEPARATOR = keccak256(abi.encode(..., block.chainid, ...));
    }

    function domainSeparator() public view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }
}

// Good - recalculates if chain ID changes
contract Token {
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    constructor() {
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
        _CACHED_CHAIN_ID = block.chainid;
    }

    function domainSeparator() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator();
        }
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(name) = &func_def.name else {
                return Vec::new();
            };

            if !Self::is_domain_separator_name(&name.name) {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            // If function body contains chainid check, skip
            let chainid_findings = find_in_statement(body, file, self.id(), |expr| {
                Self::matches_chainid(expr)
            });

            if !chainid_findings.is_empty() {
                return Vec::new();
            }

            // Flag: domainSeparator function without chainid check
            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&name.loc, file),
            }
            .into()
        });
    }
}

impl DomainSeparatorReplayDetector {
    fn is_domain_separator_name(name: &str) -> bool {
        let name_lower = name.to_lowercase();
        if name_lower.contains("domain") && name_lower.contains("separator") {
            if let Some(domain_pos) = name_lower.find("domain") {
                let after_domain = domain_pos + "domain".len();
                if let Some(separator_pos) = name_lower.find("separator") {
                    // Allow 0 or 1 character between (domainSeparator, domain_separator)
                    let chars_between = separator_pos - after_domain;
                    return chars_between <= 1;
                }
            }
        }
        false
    }

    fn matches_chainid(expr: &Expression) -> bool {
        match expr {
            // block.chainid
            Expression::MemberAccess(_, obj, member) => {
                if member.name.to_lowercase() == "chainid" {
                    if let Expression::Variable(ident) = obj.as_ref() {
                        return ident.name.to_lowercase() == "block";
                    }
                }
                false
            }
            // chainid variable
            Expression::Variable(ident) => ident.name.to_lowercase() == "chainid",
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_domain_separator_without_chainid_check() {
        let code = r#"
            contract Token {
                bytes32 private immutable _DOMAIN_SEPARATOR;

                function domainSeparator() public view returns (bytes32) {
                    return _DOMAIN_SEPARATOR;
                }
            }
        "#;
        let detector = Arc::new(DomainSeparatorReplayDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 5, "domainSeparator without chainid check");
    }

    #[test]
    fn test_skips_domain_separator_with_chainid_check() {
        let code = r#"
            contract Token {
                bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
                uint256 private immutable _CACHED_CHAIN_ID;

                function domainSeparator() public view returns (bytes32) {
                    if (block.chainid == _CACHED_CHAIN_ID) {
                        return _CACHED_DOMAIN_SEPARATOR;
                    } else {
                        return _buildDomainSeparator();
                    }
                }
            }
        "#;
        let detector = Arc::new(DomainSeparatorReplayDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
