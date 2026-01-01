use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, Location, SolidityFile, TypeInfo};
use crate::utils::ast_utils::{find_locations_in_statement, get_contract_info};
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{ContractPart, Expression, Loc, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MissingZeroAddressValidationDetector;

impl Detector for MissingZeroAddressValidationDetector {
    fn id(&self) -> &'static str {
        "missing-zero-address-validation"
    }

    fn name(&self) -> &str {
        "Missing checks for `address(0)` when assigning values to address state variables"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Address state variables should be checked for zero address before assignment to prevent \
         accidentally setting critical addresses to address(0). This can lead to loss of contract \
         control or functionality. Always validate address parameters with `require(addr != address(0))` \
         or similar checks before assigning them to state variables."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no zero address check
contract Test {
    address public owner;

    function setOwner(address newOwner) public {
        owner = newOwner;  // Missing validation
    }
}

// Good - with zero address check
contract Test {
    address public owner;

    function setOwner(address newOwner) public {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let Some(contract_info) = get_contract_info(contract_def, file) else {
                return Vec::new();
            };

            let address_state_vars: HashSet<String> = contract_info
                .state_variables
                .iter()
                .filter(|v| matches!(v.type_info, TypeInfo::Address | TypeInfo::AddressPayable))
                .map(|v| v.name.clone())
                .collect();

            if address_state_vars.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    let Some(body) = &func_def.body else {
                        continue;
                    };

                    let mut predicate = |expr: &Expression, _file_ref: &SolidityFile| -> Option<Loc> {
                        if let Expression::Assign(loc, left, right) = expr {
                            // Check if left side is an address state variable
                            if let Expression::Variable(left_id) = left.as_ref() {
                                if address_state_vars.contains(&left_id.name) {
                                    // Check if right side is a variable (not a literal)
                                    if let Expression::Variable(right_id) = right.as_ref() {
                                        // Check if this variable has validation in the function
                                        if !Self::find_validation_recursive(body, &right_id.name) {
                                            return Some(loc.clone());
                                        }
                                    }
                                }
                            }
                        }
                        None
                    };
                    
                    let mut locations: Vec<Location> = Vec::new();
                    find_locations_in_statement(body, file, &mut predicate, &mut locations);

                    findings.extend(locations.into_iter().map(|location| FindingData {
                        detector_id: self.id(),
                        location,
                    }));
                }
            }

            findings
        });
    }
}

impl MissingZeroAddressValidationDetector {
    fn find_validation_recursive(stmt: &Statement, var_name: &str) -> bool {
        match stmt {
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| Self::find_validation_recursive(s, var_name))
            }
            Statement::Expression(_, expr) => Self::expr_has_validation(expr, var_name),
            Statement::If(_, cond, then_stmt, else_stmt) => {
                Self::expr_has_validation(cond, var_name)
                    || Self::find_validation_recursive(then_stmt, var_name)
                    || else_stmt.as_ref().map_or(false, |s| Self::find_validation_recursive(s, var_name))
            }
            Statement::While(_, cond, body) => {
                Self::expr_has_validation(cond, var_name) || Self::find_validation_recursive(body, var_name)
            }
            Statement::DoWhile(_, body, cond) => {
                Self::find_validation_recursive(body, var_name) || Self::expr_has_validation(cond, var_name)
            }
            Statement::For(_, _, cond, _, body) => {
                cond.as_ref().map_or(false, |c| Self::expr_has_validation(c, var_name))
                    || body.as_ref().map_or(false, |b| Self::find_validation_recursive(b, var_name))
            }
            Statement::Return(_, Some(expr)) => Self::expr_has_validation(expr, var_name),
            _ => false,
        }
    }

    fn expr_has_validation(expr: &Expression, var_name: &str) -> bool {
        match expr {
            // == or != 
            Expression::Equal(_, left, right) | Expression::NotEqual(_, left, right) => {
                Self::is_variable_with_name(left, var_name) || Self::is_variable_with_name(right, var_name)
            }
            // require/assert
            Expression::FunctionCall(_, _, args) => {
                args.iter().any(|arg| Self::expr_has_validation(arg, var_name))
            }
            // negation
            Expression::Not(_, inner) => Self::expr_has_validation(inner, var_name),
            // logical operators (&&, ||)
            Expression::And(_, left, right)
            | Expression::Or(_, left, right) => {
                Self::expr_has_validation(left, var_name) || Self::expr_has_validation(right, var_name)
            }
            _ => false,
        }
    }

    fn is_variable_with_name(expr: &Expression, name: &str) -> bool {
        matches!(expr, Expression::Variable(id) if id.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_validation() {
        let code = r#"
            contract Test {
                address public owner;
                address public admin;

                function setOwner(address newOwner) public {
                    owner = newOwner;
                }

                function setAddresses(address newOwner, address newAdmin) public {
                    owner = newOwner;
                    admin = newAdmin;
                }
            }
        "#;
        let detector = Arc::new(MissingZeroAddressValidationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 7, "owner = newOwner");
        assert_eq!(locations[1].line, 11, "owner = newOwner");
        assert_eq!(locations[2].line, 12, "admin = newAdmin");
    }

    #[test]
    fn test_skips_with_validation() {
        let code = r#"
            contract Test {
                address public owner;

                function setOwner(address newOwner) public {
                    require(newOwner != address(0), "Zero address");
                    owner = newOwner;
                }

                function setOwner2(address newOwner) public {
                    if (newOwner == address(0)) revert();
                    owner = newOwner;
                }

                function setOwner3(address newOwner) public {
                    assert(newOwner != address(0));
                    owner = newOwner;
                }

                function setOwner4(address newOwner, bool _paused) public {
                    require(!_paused && newOwner != address(0), "Invalid");
                    owner = newOwner;
                }

                function resetOwner() public {
                    owner = address(0);
                }
            }
        "#;
        let detector = Arc::new(MissingZeroAddressValidationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
