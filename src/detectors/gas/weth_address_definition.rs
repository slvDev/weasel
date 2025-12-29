use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::VariableDefinition;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct WethAddressDefinitionDetector;

impl Detector for WethAddressDefinitionDetector {
    fn id(&self) -> &'static str {
        "weth-address-definition"
    }

    fn name(&self) -> &str {
        "WETH Address Definition"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "WETH is a wrapped Ether contract with a specific address on the Ethereum network \
         (0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2). Defining it as a variable wastes gas. \
         Use the hardcoded address directly to save gas, prevent incorrect definitions, \
         and avoid issues when executing on different chains."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - wastes gas with variable storage
address public weth;
address immutable WETH;

constructor(address _weth) {
    weth = _weth;
    WETH = _weth;
}

// Good - use hardcoded address directly
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
// Or just use the address directly in code without storing it
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var, file, _context| {
            if Self::is_weth_variable(var) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&var.loc, file),
                }
                .into();
            }
            Vec::new()
        });
    }
}

impl WethAddressDefinitionDetector {
    /// Check if variable name contains "weth" (case insensitive)
    fn is_weth_variable(var: &VariableDefinition) -> bool {
        if let Some(name) = &var.name {
            let var_name = name.name.to_lowercase();
            var_name.contains("weth")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_weth_variable_definitions() {
        let code = r#"
            contract Test {
                address public weth;
                address immutable WETH;
                IWETH private wethToken;
            }
        "#;
        let detector = Arc::new(WethAddressDefinitionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "address public weth");
        assert_eq!(locations[1].line, 4, "address immutable WETH");
        assert_eq!(locations[2].line, 5, "IWETH private wethToken");
    }

    #[test]
    fn test_skips_non_weth_variables() {
        let code = r#"
            contract Test {
                address public token;
                address immutable uniswap;
                IERC20 private dai;
            }
        "#;
        let detector = Arc::new(WethAddressDefinitionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
