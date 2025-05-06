use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::utils::version::solidity_version_req_matches;
use solang_parser::pt::Expression;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct PreferConcatDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for PreferConcatDetector {
    fn id(&self) -> &str {
        "prefer-concat"
    }

    fn name(&self) -> &str {
        "Prefer `string.concat()`/`bytes.concat()` over `abi.encodePacked()`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Solidity v0.8.4 introduced `bytes.concat()` and v0.8.12 introduced `string.concat()`. \
        These functions are generally preferred over `abi.encodePacked` for simple concatenation \
        as they provide type safety and clearer intent, especially for strings."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// For Solidity >= 0.8.4 (bytes) or >= 0.8.12 (string)

// Instead of:
// bytes memory data = abi.encodePacked(bytes1, bytes2);
// string memory greeting = abi.encodePacked("Hello, ", name);

// Consider using:
// bytes memory data = bytes.concat(bytes1, bytes2); // Since 0.8.4
// string memory greeting = string.concat("Hello, ", name); // Since 0.8.12
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_expression(move |expr, file| {
            let version_is_gte_0_8 = match &file.solidity_version {
                Some(version_str) => solidity_version_req_matches(version_str, ">=0.8.4"),
                None => false,
            };

            if !version_is_gte_0_8 {
                return;
            }

            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                if let Expression::MemberAccess(_member_loc, base_expr, member_ident) =
                    func_expr.as_ref()
                {
                    if let Expression::Variable(abi_ident) = base_expr.as_ref() {
                        if abi_ident.name == "abi" && member_ident.name == "encodePacked" {
                            detector_arc.add_location(loc_to_location(loc, file));
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_prefer_concat_detector() {
        let code = r#"
            pragma solidity ^0.8.4;
            contract Contract {
                bytes b1 = hex"01";
                bytes b2 = hex"02";
                function foo() public view returns (bytes memory) {
                    return abi.encodePacked(b1, b2);
                }
            }
        "#;
        let detector = Arc::new(PreferConcatDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1, "Should detect in >=0.8.4");
        assert_eq!(locations[0].line, 7);

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("abi.encodePacked(b1, b2)"),
            "Snippet for first assert is incorrect"
        );

        let code = r#"
            pragma solidity ^0.8.12;
            contract Contract {
                string s1 = "Hello";
                string s2 = " World";
                function foo() public view returns (string memory) {
                    return abi.encodePacked(s1, s2);
                }
            }
        "#;
        let detector = Arc::new(PreferConcatDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1, "Should detect in >=0.8.12");
        assert_eq!(locations[0].line, 7);

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("abi.encodePacked(s1, s2)"),
            "Snippet for first assert is incorrect"
        );

        let code = r#"
            pragma solidity ^0.7.0;
            contract Contract {
                bytes b1 = hex"01";
                function foo() public view returns (bytes memory) {
                    return abi.encodePacked(b1);
                }
            }
        "#;
        let detector = Arc::new(PreferConcatDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should NOT detect in <0.8.4");

        let code = r#"
            pragma solidity ^0.8.4;
            contract Contract {
                bytes b1 = hex"01";
                bytes b2 = hex"02";
                function foo() public view returns (bytes memory) {
                    return bytes.concat(b1, b2);
                }
            }
        "#;
        let detector = Arc::new(PreferConcatDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should NOT detect correct usage");
    }
}
