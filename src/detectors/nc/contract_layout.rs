use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractPart, FunctionTy, Loc};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ContractLayoutDetector;

impl Detector for ContractLayoutDetector {
    fn id(&self) -> &'static str {
        "contract-layout"
    }

    fn name(&self) -> &str {
        "Contract does not follow the Solidity style guide's suggested layout ordering"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "According to the Solidity style guide, within a contract the ordering should be: \
         1) Type declarations (using, enums, structs, type definitions) \
         2) State variables \
         3) Events \
         4) Errors \
         5) Modifiers \
         6) Functions"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
contract Example {
    function foo() external {}
    uint256 stateVar;
    event Transfer();
}

// Good
contract Example {
    uint256 stateVar;
    event Transfer();
    function foo() external {}
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut parts: Vec<(u8, Loc)> = Vec::new();

            for part in &contract_def.parts {
                let (order, loc) = Self::get_part_order(part);
                if order > 0 {
                    parts.push((order, loc));
                }
            }

            let mut sorted_orders: Vec<u8> = parts.iter().map(|(o, _)| *o).collect();
            sorted_orders.sort();

            let mut findings = Vec::new();
            for (i, (order, loc)) in parts.iter().enumerate() {
                if *order != sorted_orders[i] {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    });
                }
            }

            findings
        });
    }
}

impl ContractLayoutDetector {
    fn get_part_order(part: &ContractPart) -> (u8, Loc) {
        // Order based on Solidity style guide:
        // 1. Using directives
        // 2. Type declarations (enums, structs, type definitions)
        // 3. State variables
        // 4. Events
        // 5. Errors
        // 6. Modifiers
        // 7. Functions
        match part {
            ContractPart::Using(using) => (1, using.loc),
            ContractPart::EnumDefinition(e) => (2, e.loc),
            ContractPart::StructDefinition(s) => (2, s.loc),
            ContractPart::TypeDefinition(t) => (2, t.loc),
            ContractPart::VariableDefinition(v) => (3, v.loc),
            ContractPart::EventDefinition(e) => (4, e.loc),
            ContractPart::ErrorDefinition(e) => (5, e.loc),
            ContractPart::FunctionDefinition(f) => {
                if matches!(f.ty, FunctionTy::Modifier) {
                    (6, f.loc)
                } else {
                    (7, f.loc)
                }
            }
            _ => (0, Loc::Builtin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_wrong_layout() {
        let code = r#"
            contract Test {
                function foo() external {}
                modifier onlyOwner() { _; }
                error Unauthorized();
                event Transfer();
                uint256 stateVar;
                struct Data { uint256 x; }
                enum Status { Active, Inactive }
                using Math for uint256;
            }
        "#;
        let detector = Arc::new(ContractLayoutDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 8);
        assert_eq!(locations[0].line, 3, "function");
        assert_eq!(locations[1].line, 4, "modifier");
        assert_eq!(locations[2].line, 5, "error");
        assert_eq!(locations[3].line, 6, "event");
        assert_eq!(locations[4].line, 7, "stateVar");
        assert_eq!(locations[5].line, 8, "struct");
        assert_eq!(locations[6].line, 9, "enum");
        assert_eq!(locations[7].line, 10, "using");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                using Math for uint256;
                enum Status { Active, Inactive }
                struct Data { uint256 x; }
                uint256 stateVar;
                event Transfer();
                error Unauthorized();
                modifier onlyOwner() { _; }
                function foo() external {}
            }
        "#;
        let detector = Arc::new(ContractLayoutDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
