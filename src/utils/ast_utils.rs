use std::path::Path;

use crate::{
    models::{
        finding::{FindingData, Location},
        ContractInfo, ContractType, ImportInfo, SolidityFile,
    },
    utils::location::loc_to_location,
};
use solang_parser::pt::{
    ContractDefinition, ContractPart, Expression, Import, Loc, PragmaDirective, SourceUnit,
    SourceUnitPart, Statement, Type, VariableDefinition, VersionComparator, VersionOp,
};
fn find_locations_in_expression_recursive<P>(
    expression: &Expression,
    file: &SolidityFile,
    predicate: &mut P,
    found_locations: &mut Vec<Location>,
) where
    P: FnMut(&Expression, &SolidityFile) -> Option<Loc>,
{
    if let Some(loc) = predicate(expression, file) {
        found_locations.push(loc_to_location(&loc, file));
    }

    match expression {
        Expression::PostIncrement(_, sub_expr)
        | Expression::PostDecrement(_, sub_expr)
        | Expression::PreIncrement(_, sub_expr)
        | Expression::PreDecrement(_, sub_expr)
        | Expression::UnaryPlus(_, sub_expr)
        | Expression::Negate(_, sub_expr)
        | Expression::Not(_, sub_expr)
        | Expression::BitwiseNot(_, sub_expr)
        | Expression::Delete(_, sub_expr)
        | Expression::New(_, sub_expr)
        | Expression::Parenthesis(_, sub_expr) => {
            find_locations_in_expression_recursive(sub_expr, file, predicate, found_locations);
        }

        Expression::Power(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::ShiftLeft(_, left, right)
        | Expression::ShiftRight(_, left, right)
        | Expression::BitwiseAnd(_, left, right)
        | Expression::BitwiseXor(_, left, right)
        | Expression::BitwiseOr(_, left, right)
        | Expression::Less(_, left, right)
        | Expression::More(_, left, right)
        | Expression::LessEqual(_, left, right)
        | Expression::MoreEqual(_, left, right)
        | Expression::Equal(_, left, right)
        | Expression::NotEqual(_, left, right)
        | Expression::And(_, left, right)
        | Expression::Or(_, left, right) => {
            find_locations_in_expression_recursive(left, file, predicate, found_locations);
            find_locations_in_expression_recursive(right, file, predicate, found_locations);
        }

        Expression::Assign(_, left, right)
        | Expression::AssignOr(_, left, right)
        | Expression::AssignAnd(_, left, right)
        | Expression::AssignXor(_, left, right)
        | Expression::AssignShiftLeft(_, left, right)
        | Expression::AssignShiftRight(_, left, right)
        | Expression::AssignAdd(_, left, right)
        | Expression::AssignSubtract(_, left, right)
        | Expression::AssignMultiply(_, left, right)
        | Expression::AssignDivide(_, left, right)
        | Expression::AssignModulo(_, left, right) => {
            find_locations_in_expression_recursive(left, file, predicate, found_locations);
            find_locations_in_expression_recursive(right, file, predicate, found_locations);
        }

        Expression::ConditionalOperator(_, condition, true_branch, false_branch) => {
            find_locations_in_expression_recursive(condition, file, predicate, found_locations);
            find_locations_in_expression_recursive(true_branch, file, predicate, found_locations);
            find_locations_in_expression_recursive(false_branch, file, predicate, found_locations);
        }

        Expression::ArraySubscript(_, array, index_opt) => {
            find_locations_in_expression_recursive(array, file, predicate, found_locations);
            if let Some(index) = index_opt {
                find_locations_in_expression_recursive(index, file, predicate, found_locations);
            }
        }
        Expression::ArraySlice(_, array, start_opt, end_opt) => {
            find_locations_in_expression_recursive(array, file, predicate, found_locations);
            if let Some(start) = start_opt {
                find_locations_in_expression_recursive(start, file, predicate, found_locations);
            }
            if let Some(end) = end_opt {
                find_locations_in_expression_recursive(end, file, predicate, found_locations);
            }
        }
        Expression::ArrayLiteral(_, elements) => {
            for element in elements {
                find_locations_in_expression_recursive(element, file, predicate, found_locations);
            }
        }

        Expression::FunctionCall(_, function, args) => {
            find_locations_in_expression_recursive(function, file, predicate, found_locations);
            for arg in args {
                find_locations_in_expression_recursive(arg, file, predicate, found_locations);
            }
        }
        Expression::FunctionCallBlock(_, function, block) => {
            find_locations_in_expression_recursive(function, file, predicate, found_locations);
            find_locations_in_statement_recursive(block, file, predicate, found_locations);
        }
        Expression::NamedFunctionCall(_, function, args) => {
            find_locations_in_expression_recursive(function, file, predicate, found_locations);
            for arg in args {
                find_locations_in_expression_recursive(&arg.expr, file, predicate, found_locations);
            }
        }

        Expression::MemberAccess(_, object, _) => {
            find_locations_in_expression_recursive(object, file, predicate, found_locations);
        }

        Expression::Type(_, ty_expr) => match ty_expr {
            Type::Mapping { key, value, .. } => {
                find_locations_in_expression_recursive(key, file, predicate, found_locations);
                find_locations_in_expression_recursive(value, file, predicate, found_locations);
            }
            _ => {}
        },

        Expression::BoolLiteral(..)
        | Expression::NumberLiteral(..)
        | Expression::RationalNumberLiteral(..)
        | Expression::HexNumberLiteral(..)
        | Expression::StringLiteral(..)
        | Expression::HexLiteral(..)
        | Expression::AddressLiteral(..)
        | Expression::Variable(_)
        | Expression::List(..) => {}
    }
}

pub fn find_locations_in_statement_recursive<P>(
    statement: &Statement,
    file: &SolidityFile,
    predicate: &mut P,
    found_locations: &mut Vec<Location>,
) where
    P: FnMut(&Expression, &SolidityFile) -> Option<Loc>,
{
    match statement {
        Statement::Block { statements, .. } => {
            for stmt in statements {
                find_locations_in_statement_recursive(stmt, file, predicate, found_locations);
            }
        }
        Statement::If(_, condition, true_branch, false_branch_opt) => {
            find_locations_in_expression_recursive(condition, file, predicate, found_locations);
            find_locations_in_statement_recursive(true_branch, file, predicate, found_locations);
            if let Some(false_branch) = false_branch_opt {
                find_locations_in_statement_recursive(
                    false_branch,
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::While(_, condition, body) => {
            find_locations_in_expression_recursive(condition, file, predicate, found_locations);
            find_locations_in_statement_recursive(body, file, predicate, found_locations);
        }
        Statement::DoWhile(_, body, condition) => {
            find_locations_in_statement_recursive(body, file, predicate, found_locations);
            find_locations_in_expression_recursive(condition, file, predicate, found_locations);
        }
        Statement::For(_, init_opt, condition_opt, update_opt, body_opt) => {
            if let Some(init_stmt_box) = init_opt {
                find_locations_in_statement_recursive(
                    init_stmt_box.as_ref(),
                    file,
                    predicate,
                    found_locations,
                );
            }
            if let Some(condition_expr) = condition_opt {
                find_locations_in_expression_recursive(
                    condition_expr,
                    file,
                    predicate,
                    found_locations,
                );
            }
            if let Some(update_expr) = update_opt {
                // update_opt is Box<Expression>, so dereference for the function call
                find_locations_in_expression_recursive(
                    update_expr.as_ref(),
                    file,
                    predicate,
                    found_locations,
                );
            }
            if let Some(body_stmt_box) = body_opt {
                find_locations_in_statement_recursive(
                    body_stmt_box.as_ref(),
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::Expression(_, expr_box) => {
            find_locations_in_expression_recursive(expr_box, file, predicate, found_locations);
        }
        Statement::VariableDefinition(_, var_def, init_expr_opt) => {
            // Type of the variable can be an expression (e.g. mapping)
            find_locations_in_expression_recursive(&var_def.ty, file, predicate, found_locations);
            if let Some(init_expr_box) = init_expr_opt {
                find_locations_in_expression_recursive(
                    init_expr_box,
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::Return(_, expr_opt) => {
            if let Some(expr_box) = expr_opt {
                find_locations_in_expression_recursive(expr_box, file, predicate, found_locations);
            }
        }
        Statement::Emit(_, expr_box) => {
            find_locations_in_expression_recursive(expr_box, file, predicate, found_locations);
        }
        Statement::Revert(_, _, args) => {
            for arg_expr_box in args {
                find_locations_in_expression_recursive(
                    arg_expr_box,
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::RevertNamedArgs(_, _, named_args) => {
            for named_arg in named_args {
                find_locations_in_expression_recursive(
                    &named_arg.expr,
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::Try(_, expr_box, returns_opt, catch_clauses) => {
            find_locations_in_expression_recursive(expr_box, file, predicate, found_locations);
            if let Some((_, returns_block_box)) = returns_opt {
                find_locations_in_statement_recursive(
                    returns_block_box.as_ref(),
                    file,
                    predicate,
                    found_locations,
                );
            }
            for catch_clause in catch_clauses {
                match catch_clause {
                    solang_parser::pt::CatchClause::Simple(_, _, stmt_box)
                    | solang_parser::pt::CatchClause::Named(_, _, _, stmt_box) => {
                        find_locations_in_statement_recursive(
                            stmt_box,
                            file,
                            predicate,
                            found_locations,
                        );
                    }
                }
            }
        }
        Statement::Args(_, named_args) => {
            for named_arg in named_args {
                find_locations_in_expression_recursive(
                    &named_arg.expr,
                    file,
                    predicate,
                    found_locations,
                );
            }
        }
        Statement::Assembly { .. }
        | Statement::Continue(_)
        | Statement::Break(_)
        | Statement::Error(_) => {}
    }
}

pub fn find_locations_in_statement<P>(
    statement: &Statement,
    file: &SolidityFile,
    predicate: &mut P,
    found_locations: &mut Vec<Location>,
) where
    P: FnMut(&Expression, &SolidityFile) -> Option<Loc>,
{
    find_locations_in_statement_recursive(statement, file, predicate, found_locations);
}

pub fn find_locations_in_expression<P>(
    expression: &Expression,
    file: &SolidityFile,
    predicate: &mut P,
    found_locations: &mut Vec<Location>,
) where
    P: FnMut(&Expression, &SolidityFile) -> Option<Loc>,
{
    find_locations_in_expression_recursive(expression, file, predicate, found_locations);
}

/// Generic utility to find patterns in expressions with callback-based detection
pub fn find_in_expression<F>(
    expr: &Expression,
    file: &SolidityFile,
    detector_id: &'static str,
    mut predicate: F,
) -> Vec<FindingData>
where
    F: FnMut(&Expression) -> bool,
{
    let mut findings = Vec::new();
    find_in_expression_recursive(expr, file, detector_id, &mut predicate, &mut findings);
    findings
}

fn find_in_expression_recursive<F>(
    expr: &Expression,
    file: &SolidityFile,
    detector_id: &'static str,
    predicate: &mut F,
    findings: &mut Vec<FindingData>,
) where
    F: FnMut(&Expression) -> bool,
{
    // Check current expression
    if predicate(expr) {
        if let Some(loc) = get_expression_location(expr) {
            findings.push(FindingData {
                detector_id,
                location: loc_to_location(&loc, file),
            });
        }
    }

    // Recursively check sub-expressions
    match expr {
        // Binary expressions
        Expression::Less(_, left, right)
        | Expression::LessEqual(_, left, right)
        | Expression::More(_, left, right)
        | Expression::MoreEqual(_, left, right)
        | Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Assign(_, left, right) => {
            find_in_expression_recursive(left, file, detector_id, predicate, findings);
            find_in_expression_recursive(right, file, detector_id, predicate, findings);
        }
        // Unary expressions
        Expression::Parenthesis(_, inner) | Expression::Negate(_, inner) => {
            find_in_expression_recursive(inner, file, detector_id, predicate, findings);
        }
        // Member access
        Expression::MemberAccess(_, expr, _) => {
            find_in_expression_recursive(expr, file, detector_id, predicate, findings);
        }
        // Function calls
        Expression::FunctionCall(_, func_expr, args) => {
            find_in_expression_recursive(func_expr, file, detector_id, predicate, findings);
            for arg in args {
                find_in_expression_recursive(arg, file, detector_id, predicate, findings);
            }
        }
        _ => {}
    }
}

/// Generic utility to find patterns in statements with callback-based detection
pub fn find_in_statement<F>(
    stmt: &Statement,
    file: &SolidityFile,
    detector_id: &'static str,
    mut predicate: F,
) -> Vec<FindingData>
where
    F: FnMut(&Expression) -> bool,
{
    let mut findings = Vec::new();
    find_in_statement_recursive(stmt, file, detector_id, &mut predicate, &mut findings);
    findings
}

fn find_in_statement_recursive<F>(
    stmt: &Statement,
    file: &SolidityFile,
    detector_id: &'static str,
    predicate: &mut F,
    findings: &mut Vec<FindingData>,
) where
    F: FnMut(&Expression) -> bool,
{
    match stmt {
        Statement::Block { statements, .. } => {
            for inner_stmt in statements {
                find_in_statement_recursive(inner_stmt, file, detector_id, predicate, findings);
            }
        }
        Statement::Expression(_, expr) => {
            find_in_expression_recursive(expr, file, detector_id, predicate, findings);
        }
        Statement::VariableDefinition(_, _, expr_opt) => {
            if let Some(expr) = expr_opt {
                find_in_expression_recursive(expr, file, detector_id, predicate, findings);
            }
        }
        Statement::If(_, condition, then_stmt, else_stmt_opt) => {
            find_in_expression_recursive(condition, file, detector_id, predicate, findings);
            find_in_statement_recursive(then_stmt, file, detector_id, predicate, findings);
            if let Some(else_stmt) = else_stmt_opt {
                find_in_statement_recursive(else_stmt, file, detector_id, predicate, findings);
            }
        }
        Statement::While(_, condition, body) | Statement::DoWhile(_, body, condition) => {
            find_in_expression_recursive(condition, file, detector_id, predicate, findings);
            find_in_statement_recursive(body, file, detector_id, predicate, findings);
        }
        Statement::For(_, init_opt, condition_opt, post_opt, body_opt) => {
            if let Some(init) = init_opt {
                find_in_statement_recursive(init, file, detector_id, predicate, findings);
            }
            if let Some(condition) = condition_opt {
                find_in_expression_recursive(condition, file, detector_id, predicate, findings);
            }
            if let Some(post) = post_opt {
                find_in_expression_recursive(post, file, detector_id, predicate, findings);
            }
            if let Some(body) = body_opt {
                find_in_statement_recursive(body, file, detector_id, predicate, findings);
            }
        }
        _ => {}
    }
}

/// Helper function to get location from any expression
fn get_expression_location(expr: &Expression) -> Option<Loc> {
    match expr {
        Expression::ArraySubscript(loc, _, _)
        | Expression::MemberAccess(loc, _, _)
        | Expression::Less(loc, _, _)
        | Expression::More(loc, _, _)
        | Expression::LessEqual(loc, _, _)
        | Expression::MoreEqual(loc, _, _)
        | Expression::Equal(loc, _, _)
        | Expression::NotEqual(loc, _, _)
        | Expression::Add(loc, _, _)
        | Expression::Subtract(loc, _, _)
        | Expression::Multiply(loc, _, _)
        | Expression::Divide(loc, _, _)
        | Expression::Modulo(loc, _, _)
        | Expression::Assign(loc, _, _)
        | Expression::Parenthesis(loc, _)
        | Expression::Negate(loc, _)
        | Expression::FunctionCall(loc, _, _) => Some(loc.clone()),
        Expression::Variable(ident) => Some(ident.loc.clone()),
        _ => None,
    }
}

pub fn extract_imports(source_unit: &SourceUnit) -> Result<Vec<ImportInfo>, String> {
    let mut imports = Vec::new();

    for part in &source_unit.0 {
        if let SourceUnitPart::ImportDirective(import) = part {
            let import_info = process_import_directive(import)?;
            imports.push(import_info);
        }
    }

    Ok(imports)
}

/// Process a single import directive
pub fn process_import_directive(import: &Import) -> Result<ImportInfo, String> {
    use solang_parser::pt::ImportPath;

    // Extract import path and symbols based on import type
    let (path_literal, symbols) = match import {
        Import::Plain(literal, _loc) => {
            // Simple import without specific symbols: import "hardhat/console.sol";
            (Some(literal), Vec::new())
        }
        Import::GlobalSymbol(literal, symbol, _loc) => {
            // Import with global symbol: import <0> as <1>;
            let symbols = vec![symbol.name.clone()];
            (Some(literal), symbols)
        }
        Import::Rename(literal, symbol_list, _loc) => {
            // Import with renamed symbols: import { console2 as console } from "forge-std/console2.sol";
            let symbols = symbol_list
                .iter()
                .map(|(original, alias)| {
                    // Use alias if provided, otherwise use original name
                    alias
                        .as_ref()
                        .map(|a| a.name.clone())
                        .unwrap_or_else(|| original.name.clone())
                })
                .collect();
            (Some(literal), symbols)
        }
    };

    // Extract actual import path string
    let import_path = if let Some(ImportPath::Filename(filepath)) = path_literal {
        filepath.string.clone()
    } else {
        return Err("Invalid import path format".to_string());
    };

    Ok(ImportInfo {
        import_path,
        resolved_path: None, // Will be resolved later if needed
        symbols,
    })
}

/// Formats a VersionOp into its string representation.
/// Returns None for operators not directly supported by semver::VersionReq.
fn format_version_op(op: &VersionOp) -> Option<&'static str> {
    match op {
        VersionOp::GreaterEq => Some(">="),
        VersionOp::Greater => Some(">"),
        VersionOp::LessEq => Some("<="),
        VersionOp::Less => Some("<"),
        VersionOp::Exact => Some("="), // Represent plain version, e.g., pragma solidity =0.8.0;
        VersionOp::Caret => Some("^"),
        VersionOp::Tilde => Some("~"),
        VersionOp::Wildcard => None, // Wildcard operator not supported
    }
}

/// Formats a single VersionComparator into a string suitable for semver parsing.
/// Returns None if the comparator uses unsupported features (like Or, Wildcard).
fn format_version_comparator(comp: &VersionComparator) -> Option<String> {
    match comp {
        VersionComparator::Plain { version, .. } => Some(version.join(".")),
        VersionComparator::Operator { op, version, .. } => {
            format_version_op(op).map(|op_str| format!("{}{}", op_str, version.join(".")))
        }
        // Convert Solidity range "A - B" into semver range ">=A <=B"
        VersionComparator::Range { from, to, .. } => {
            Some(format!(">= {} <= {}", from.join("."), to.join(".")))
        }
        // The semver crate does not support OR logic directly in VersionReq::parse
        VersionComparator::Or { .. } => None,
    }
}

/// Extracts the solidity version requirement string from a pragma directive.
pub fn extract_solidity_version_from_pragma(pragma: &PragmaDirective) -> Option<String> {
    match pragma {
        PragmaDirective::Version(_loc, ident, version_req) if ident.name == "solidity" => {
            let mut formatted_parts = Vec::new();
            for comp in version_req {
                match format_version_comparator(comp) {
                    Some(part) => formatted_parts.push(part),
                    None => return None,
                }
            }
            if formatted_parts.is_empty() {
                None
            } else {
                Some(formatted_parts.join(" "))
            }
        }
        _ => None,
    }
}

/// Extract contract information from source unit
fn extract_contracts(
    source_unit: &SourceUnit,
    file_path: &Path,
) -> Result<Vec<ContractInfo>, String> {
    let mut contracts = Vec::new();

    for part in &source_unit.0 {
        if let SourceUnitPart::ContractDefinition(contract_def) = part {
            let contract_info = extract_contract_info(contract_def, file_path)?;
            contracts.push(contract_info);
        }
    }

    Ok(contracts)
}

/// Extract state variables from a contract definition
pub fn extract_state_variables(contract_def: &ContractDefinition) -> Vec<String> {
    let mut state_variables = Vec::new();

    for part in &contract_def.parts {
        if let ContractPart::VariableDefinition(var_def) = part {
            if let Some(name) = &var_def.name {
                state_variables.push(name.name.clone());
            }
        }
    }

    state_variables
}

/// Extract information from a single contract definition
pub fn extract_contract_info(
    contract_def: &ContractDefinition,
    file_path: &Path,
) -> Result<ContractInfo, String> {
    let name = contract_def.name.as_ref().ok_or("Unnamed contract found")?;

    let contract_type = match contract_def.ty {
        solang_parser::pt::ContractTy::Abstract(_) => ContractType::Abstract,
        solang_parser::pt::ContractTy::Contract(_) => ContractType::Contract,
        solang_parser::pt::ContractTy::Interface(_) => ContractType::Interface,
        solang_parser::pt::ContractTy::Library(_) => ContractType::Library,
    };

    // Extract direct base contracts from inheritance list
    let direct_bases: Vec<String> = contract_def
        .base
        .iter()
        .map(|base| {
            base.name
                .identifiers
                .last() // Safer that first, but in solidity should only ONE identifier
                .map(|ident| ident.name.clone())
                .unwrap_or_default()
        })
        .collect();

    // Extract state variables
    let state_variables = extract_state_variables(contract_def);

    // Extract function definitions
    let function_definitions = contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::FunctionDefinition(func_def) = part {
                func_def.name.as_ref().map(|n| n.name.clone())
            } else {
                None
            }
        })
        .collect();

    Ok(ContractInfo {
        name: name.name.clone(),
        contract_type,
        file_path: file_path.to_string_lossy().to_string(),
        direct_bases,
        inheritance_chain: Vec::new(), // Will be populated in second pass
        state_variables,
        function_definitions,
    })
}
