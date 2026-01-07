use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{
    ContractPart, FunctionAttribute, FunctionDefinition, FunctionTy, Visibility,
};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct FunctionOrderDetector;

impl Detector for FunctionOrderDetector {
    fn id(&self) -> &'static str {
        "function-order"
    }

    fn name(&self) -> &str {
        "Function ordering does not follow the Solidity style guide"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "According to the Solidity style guide, functions should be laid out in the following \
         order: constructor, receive, fallback, external, public, internal, private."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
contract Example {
    function foo() private {}
    function bar() external {}
}

// Good
contract Example {
    function bar() external {}
    function foo() private {}
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut functions: Vec<(u8, &FunctionDefinition)> = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func) = part {
                    let order = Self::get_function_order(func);
                    functions.push((order, func));
                }
            }

            let mut sorted_orders: Vec<u8> = functions.iter().map(|(o, _)| *o).collect();
            sorted_orders.sort();

            let mut findings = Vec::new();
            for (i, (order, func)) in functions.iter().enumerate() {
                if *order != sorted_orders[i] {
                    let loc = func
                        .name
                        .as_ref()
                        .map(|n| loc_to_location(&n.loc, file))
                        .unwrap_or_else(|| loc_to_location(&func.loc, file));

                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: loc,
                    });
                }
            }

            findings
        });
    }
}

impl FunctionOrderDetector {
    fn get_function_order(func: &FunctionDefinition) -> u8 {
        // Order based on Solidity style guide:
        // 1. constructor
        // 2. receive
        // 3. fallback
        // 4. external
        // 5. public
        // 6. internal
        // 7. private
        match func.ty {
            FunctionTy::Constructor => 1,
            FunctionTy::Receive => 2,
            FunctionTy::Fallback => 3,
            FunctionTy::Function | FunctionTy::Modifier => {
                // Get visibility
                for attr in &func.attributes {
                    if let FunctionAttribute::Visibility(vis) = attr {
                        return match vis {
                            Visibility::External(_) => 4,
                            Visibility::Public(_) => 5,
                            Visibility::Internal(_) => 6,
                            Visibility::Private(_) => 7,
                        };
                    }
                }
                // Default to public if no visibility specified
                5
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_wrong_order() {
        let code = r#"
            contract Test {
                function privateFn() private {}
                function internalFn() internal {}
                function publicFn() public {}
                function externalFn() external {}
                fallback() external {}
                receive() external payable {}
                constructor() {}
            }
        "#;
        let detector = Arc::new(FunctionOrderDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 3, "privateFn");
        assert_eq!(locations[1].line, 4, "internalFn");
        assert_eq!(locations[2].line, 5, "publicFn");
        assert_eq!(locations[3].line, 7, "fallback");
        assert_eq!(locations[4].line, 8, "receive");
        assert_eq!(locations[5].line, 9, "constructor");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                constructor() {}
                receive() external payable {}
                fallback() external {}
                function externalFn() external {}
                function publicFn() public {}
                function internalFn() internal {}
                function privateFn() private {}
            }
        "#;
        let detector = Arc::new(FunctionOrderDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
