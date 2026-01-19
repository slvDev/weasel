use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_in_statement;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractPart, Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MixedIntUintStyleDetector;

impl Detector for MixedIntUintStyleDetector {
    fn id(&self) -> &'static str {
        "mixed-int-uint-style"
    }

    fn name(&self) -> &str {
        "Mixed usage of int/uint with int256/uint256"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "In Solidity, int256 and uint256 are the preferred type names, especially since they \
         are used for function signatures. Using int or uint instead can lead to confusion and \
         inconsistency. When a contract mixes both styles, consider replacing int/uint with \
         int256/uint256 for better clarity and uniformity."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - mixed usage in same contract
contract Mixed {
    uint public a;      // implicit
    uint256 public b;   // explicit
}

// Good - consistent style
contract Consistent {
    uint256 public a;
    uint256 public b;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut implicit_int_findings: Vec<FindingData> = Vec::new();
            let mut implicit_uint_findings: Vec<FindingData> = Vec::new();
            let mut has_explicit_int256 = false;
            let mut has_explicit_uint256 = false;

            // Helper to categorize a type finding by its snippet
            let mut categorize = |finding: FindingData| {
                if let Some(snippet) = &finding.location.snippet {
                    match snippet.as_str() {
                        "int" => implicit_int_findings.push(finding),
                        "uint" => implicit_uint_findings.push(finding),
                        "int256" => has_explicit_int256 = true,
                        "uint256" => has_explicit_uint256 = true,
                        _ => {}
                    }
                }
            };

            for part in &contract_def.parts {
                match part {
                    ContractPart::VariableDefinition(var_def) => {
                        if let Expression::Type(loc, Type::Int(_) | Type::Uint(_)) = &var_def.ty {
                            categorize(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                    ContractPart::FunctionDefinition(func_def) => {
                        if let Some(body) = &func_def.body {
                            let findings = find_in_statement(body, file, self.id(), |expr| {
                                matches!(expr, Expression::Type(_, Type::Int(_) | Type::Uint(_)))
                            });
                            for finding in findings {
                                categorize(finding);
                            }
                        }
                    }
                    _ => {}
                }
            }

            let mut results = Vec::new();

            if has_explicit_int256 {
                results.extend(implicit_int_findings);
            }

            if has_explicit_uint256 {
                results.extend(implicit_uint_findings);
            }

            results
        });
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

            contract MixedUsage {
                uint public a;          // Line 5 - flagged (mixed with uint256)
                uint256 public b;       // explicit - not flagged
                int public c;           // Line 7 - flagged (mixed with int256)
                int256 public d;        // explicit - not flagged
            }
        "#;
        let detector = Arc::new(MixedIntUintStyleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues (int and uint)");
        assert_eq!(locations[0].line, 7, "int on line 7");
        assert_eq!(locations[1].line, 5, "uint on line 5");
    }

    #[test]
    fn test_skips_valid_code() {
        // Consistent usage - all explicit
        let code1 = r#"
            pragma solidity ^0.8.0;

            contract ConsistentExplicit {
                uint256 public a;
                uint256 public b;
                int256 public c;
            }
        "#;

        // Consistent usage - all implicit (no mixing)
        let code2 = r#"
            pragma solidity ^0.8.0;

            contract ConsistentImplicit {
                uint public a;
                uint public b;
                int public c;
            }
        "#;

        let detector1 = Arc::new(MixedIntUintStyleDetector::default());
        let locations1 = run_detector_on_code(detector1, code1, "test.sol");
        assert_eq!(locations1.len(), 0, "Consistent explicit should not flag");

        let detector2 = Arc::new(MixedIntUintStyleDetector::default());
        let locations2 = run_detector_on_code(detector2, code2, "test.sol");
        assert_eq!(locations2.len(), 0, "Consistent implicit should not flag");
    }
}
