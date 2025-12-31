use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::collect_function_calls;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractPart, FunctionTy, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UninitializedImplementationDetector;

impl Detector for UninitializedImplementationDetector {
    fn id(&self) -> &'static str {
        "uninitialized-implementation"
    }

    fn name(&self) -> &str {
        "Do not leave an implementation contract uninitialized"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "An uninitialized implementation contract can be taken over by an attacker, which may impact the proxy. \
         To prevent the implementation contract from being used, it's advisable to invoke the `_disableInitializers` \
         function in the constructor to automatically lock it when it is deployed. This should look similar to:\n\
         ```solidity\n\
         /// @custom:oz-upgrades-unsafe-allow constructor\n\
         constructor() {\n\
             _disableInitializers();\n\
         }\n\
         ```\n\
         Sources:\n\
         - https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable-_disableInitializers--\n\
         - https://twitter.com/0xCygaar/status/1621417995905167360?s=20"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unprotected implementation contract
contract MyImplementation is Initializable {
    function initialize() public initializer {
        // ...
    }

    constructor() {
        // Missing _disableInitializers()!
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, context| {
            if !context.contract_inherits_from(contract_def, file, "Initializable") {
                return Vec::new();
            }

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if matches!(func_def.ty, FunctionTy::Constructor) {
                        if let Some(body) = &func_def.body {
                            if !Self::calls_disable_initializers(body) {
                                return FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(&func_def.loc, file),
                                }
                                .into();
                            }
                        }
                    }
                }
            }

            Vec::new()
        });
    }
}

impl UninitializedImplementationDetector {
    fn calls_disable_initializers(stmt: &Statement) -> bool {
        let mut calls = HashSet::new();
        collect_function_calls(stmt, &mut calls);
        calls.contains("_disableInitializers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_with_mock_inheritance;

    #[test]
    fn test_detects_uninitialized_implementation() {
        let code = r#"
            contract MyImplementation is Initializable {
                constructor() {
                    // Missing _disableInitializers()
                }
            }
        "#;
        let mock_inheritance = vec![
            ("Initializable", vec!["Initializable"]),
            ("MyImplementation", vec!["Initializable", "MyImplementation"]),
        ];
        let detector = Arc::new(UninitializedImplementationDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock_inheritance);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 3, "constructor without _disableInitializers");
    }

    #[test]
    fn test_skips_with_disable_initializers() {
        let code = r#"
            contract WithDisable is Initializable {
                constructor() {
                    _disableInitializers();
                }
            }

            contract NoInheritance {
                constructor() {
                    // Should not flag - not inheriting Initializable
                }
            }

            contract NoConstructor is Initializable {
                // No constructor, so nothing to flag
            }
        "#;
        let mock_inheritance = vec![
            ("Initializable", vec!["Initializable"]),
            ("WithDisable", vec!["Initializable", "WithDisable"]),
            ("NoConstructor", vec!["Initializable", "NoConstructor"]),
        ];
        let detector = Arc::new(UninitializedImplementationDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock_inheritance);
        assert_eq!(locations.len(), 0);
    }
}
