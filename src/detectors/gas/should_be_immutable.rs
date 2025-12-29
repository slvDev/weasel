use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile, StateVariableInfo, VariableMutability};
use crate::utils::ast_utils::{find_locations_in_statement, get_contract_info};
use solang_parser::pt::{ContractPart, Expression, FunctionTy, Loc, Statement};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ShouldBeImmutableDetector;

impl Detector for ShouldBeImmutableDetector {
    fn id(&self) -> &'static str {
        "should-be-immutable"
    }

    fn name(&self) -> &str {
        "State variables only set in the constructor should be declared `immutable`"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Variables only set in the constructor and never edited afterwards should be marked as \
        immutable. This saves around 20,000 gas on deployment (avoiding SSTORE) and replaces \
        expensive storage reads (2100 gas) with cheap value reads (3 gas)."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses storage slot
contract Bad {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}

// Good - uses code space
contract Good {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            let contract_info = match get_contract_info(contract_def, file) {
                Some(info) => info,
                None => return Vec::new(),
            };

            // Filter to mutable variables with immutable-compatible types
            let state_vars: HashMap<String, Location> = contract_info
                .state_variables
                .iter()
                .filter(|v| Self::can_be_immutable(v))
                .map(|v| (v.name.clone(), v.loc.clone()))
                .collect();

            if state_vars.is_empty() {
                return Vec::new();
            }

            // Step 2: Find constructor and non-constructor functions
            let mut constructor_assigned: HashSet<String> = HashSet::new();
            let mut non_constructor_assigned: HashSet<String> = HashSet::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func) = part {
                    let is_constructor = matches!(func.ty, FunctionTy::Constructor);

                    if let Some(body) = &func.body {
                        for var_name in state_vars.keys() {
                            if Self::is_assigned_to(var_name, body, file) {
                                if is_constructor {
                                    constructor_assigned.insert(var_name.clone());
                                } else {
                                    non_constructor_assigned.insert(var_name.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Step 3: Report variables only in constructor (sorted by line)
            let mut candidates: Vec<_> = constructor_assigned
                .iter()
                .filter(|var_name| !non_constructor_assigned.contains(*var_name))
                .filter_map(|var_name| state_vars.get(var_name).map(|loc| (var_name, loc.clone())))
                .collect();

            // Sort by line number for deterministic output
            candidates.sort_by_key(|(_, loc)| loc.line);

            for (_, loc) in candidates {
                findings.push(FindingData {
                    detector_id: self.id(),
                    location: loc,
                });
            }

            findings
        });
    }
}

impl ShouldBeImmutableDetector {
    /// Check if variable can be made immutable
    fn can_be_immutable(info: &StateVariableInfo) -> bool {
        if info.mutability != VariableMutability::Mutable {
            return false;
        }

        // Types that cannot be immutable: mappings, strings, bytes, dynamic arrays
        let t = &info.type_name;
        !t.starts_with("Mapping") && t != "String" && t != "DynamicBytes" && !t.ends_with("[]")
    }

    /// Check if variable is assigned in statement
    fn is_assigned_to(var_name: &str, body: &Statement, file: &SolidityFile) -> bool {
        let var_name = var_name.to_string();
        let mut predicate = |expr: &Expression, _: &SolidityFile| -> Option<Loc> {
            if Self::is_direct_assignment_to(&var_name, expr) {
                Some(Loc::Implicit)
            } else {
                None
            }
        };

        let mut found = Vec::new();
        find_locations_in_statement(body, file, &mut predicate, &mut found);
        !found.is_empty()
    }

    /// Check if expression is a direct assignment to the variable
    fn is_direct_assignment_to(var_name: &str, expr: &Expression) -> bool {
        let left = match expr {
            Expression::Assign(_, left, _)
            | Expression::AssignAdd(_, left, _)
            | Expression::AssignSubtract(_, left, _)
            | Expression::AssignMultiply(_, left, _)
            | Expression::AssignDivide(_, left, _)
            | Expression::AssignModulo(_, left, _)
            | Expression::AssignOr(_, left, _)
            | Expression::AssignAnd(_, left, _)
            | Expression::AssignXor(_, left, _)
            | Expression::AssignShiftLeft(_, left, _)
            | Expression::AssignShiftRight(_, left, _) => left,
            _ => return false,
        };

        matches!(left.as_ref(), Expression::Variable(ident) if ident.name == var_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issues() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address public owner;
                uint256 public maxSupply;
                bytes32 public merkleRoot;

                constructor(address _owner, uint256 _max, bytes32 _root) {
                    owner = _owner;
                    maxSupply = _max;
                    merkleRoot = _root;
                }

                function getOwner() external view returns (address) {
                    return owner;
                }
            }
        "#;

        let detector = Arc::new(ShouldBeImmutableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 5, "owner");
        assert_eq!(locations[1].line, 6, "maxSupply");
        assert_eq!(locations[2].line, 7, "merkleRoot");
    }

    #[test]
    fn test_skips_invalid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                // Modified after constructor
                address public owner;
                uint256 public counter;

                // Already immutable/constant
                address public immutable admin;
                uint256 public constant MAX = 100;

                // Non-immutable types
                mapping(address => uint256) public balances;
                string public name;
                bytes public data;
                uint256[] public values;

                // Not set in constructor
                uint256 public lazyInit;

                constructor(address _owner, address _admin) {
                    owner = _owner;
                    counter = 0;
                    admin = _admin;
                }

                function setOwner(address _new) external {
                    owner = _new;
                }

                function increment() external {
                    counter += 1;
                }

                function initialize(uint256 _val) external {
                    lazyInit = _val;
                }
            }
        "#;

        let detector = Arc::new(ShouldBeImmutableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
