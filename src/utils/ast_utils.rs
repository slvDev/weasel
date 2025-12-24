use std::collections::HashSet;
use std::path::Path;

use crate::{
    models::{
        finding::{FindingData, Location},
        ContractInfo, ContractType, EnumInfo, ErrorInfo, ErrorParameter, EventInfo, EventParameter,
        FunctionInfo, FunctionMutability, FunctionParameter, FunctionType, FunctionVisibility,
        ImportInfo, ModifierInfo, ModifierParameter, SolidityFile, StateVariableInfo, StructField,
        StructInfo, TypeDefinitionInfo, UsingDirectiveInfo, VariableMutability, VariableVisibility,
    },
    utils::location::loc_to_location,
};
use solang_parser::pt::{
    ContractDefinition, ContractPart, EnumDefinition, ErrorDefinition, EventDefinition, Expression,
    FunctionAttribute, FunctionDefinition, FunctionTy, Import, Loc, Mutability, PragmaDirective,
    SourceUnit, SourceUnitPart, Statement, StructDefinition, Type, TypeDefinition, Using,
    UsingList, VariableDefinition, VersionComparator, VersionOp, Visibility,
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

/// Find all uses of a variable by name in a statement, returning their locations
pub fn find_variable_uses(var_name: &str, body: &Statement, file: &SolidityFile) -> Vec<Location> {
    let mut occurrences = Vec::new();
    let mut predicate = |expr: &Expression, _: &SolidityFile| -> Option<Loc> {
        if let Expression::Variable(ident) = expr {
            if ident.name == var_name {
                return Some(ident.loc);
            }
        }
        None
    };
    find_locations_in_statement(body, file, &mut predicate, &mut occurrences);
    occurrences
}

/// Get all local variable names in a function (parameters + return params + declarations)
pub fn get_local_variable_names(func_def: &FunctionDefinition, body: &Statement) -> HashSet<String> {
    let mut local_vars = HashSet::new();

    // Add function parameters
    for (_, param_opt) in &func_def.params {
        if let Some(param) = param_opt {
            if let Some(name) = &param.name {
                local_vars.insert(name.name.clone());
            }
        }
    }

    // Add return parameters (can be used as local variables)
    for (_, param_opt) in &func_def.returns {
        if let Some(param) = param_opt {
            if let Some(name) = &param.name {
                local_vars.insert(name.name.clone());
            }
        }
    }

    // Add local variable declarations from body
    collect_local_declarations(body, &mut local_vars);

    local_vars
}

/// Recursively collect local variable declaration names from a statement
pub fn collect_local_declarations(stmt: &Statement, local_vars: &mut HashSet<String>) {
    match stmt {
        Statement::VariableDefinition(_, decl, _) => {
            if let Some(name) = &decl.name {
                local_vars.insert(name.name.clone());
            }
        }
        Statement::Block { statements, .. } => {
            for s in statements {
                collect_local_declarations(s, local_vars);
            }
        }
        Statement::If(_, _, then_stmt, else_stmt) => {
            collect_local_declarations(then_stmt, local_vars);
            if let Some(else_s) = else_stmt {
                collect_local_declarations(else_s, local_vars);
            }
        }
        Statement::For(_, init, _, _, body_opt) => {
            if let Some(init_stmt) = init {
                collect_local_declarations(init_stmt, local_vars);
            }
            if let Some(body) = body_opt {
                collect_local_declarations(body, local_vars);
            }
        }
        Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
            collect_local_declarations(body, local_vars);
        }
        _ => {}
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

/// Extract variable information from a variable definition
pub fn extract_variable_info(var_def: &VariableDefinition) -> StateVariableInfo {
    let name = var_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let type_name = extract_type_name(&var_def.ty);

    // Determine visibility from attrs
    let visibility = var_def
        .attrs
        .iter()
        .find_map(|attr| match attr {
            solang_parser::pt::VariableAttribute::Visibility(vis) => Some(match vis {
                Visibility::Public(_) => VariableVisibility::Public,
                Visibility::Private(_) => VariableVisibility::Private,
                Visibility::Internal(_) => VariableVisibility::Internal,
                Visibility::External(_) => VariableVisibility::External,
            }),
            _ => None,
        })
        .unwrap_or(VariableVisibility::Internal); // Default visibility for state variables

    // Check for constant and immutable
    let is_constant = var_def
        .attrs
        .iter()
        .any(|attr| matches!(attr, solang_parser::pt::VariableAttribute::Constant(_)));

    let is_immutable = var_def
        .attrs
        .iter()
        .any(|attr| matches!(attr, solang_parser::pt::VariableAttribute::Immutable(_)));

    // Determine mutability
    let mutability = if is_constant {
        VariableMutability::Constant
    } else if is_immutable {
        VariableMutability::Immutable
    } else {
        VariableMutability::Mutable
    };

    StateVariableInfo {
        name,
        type_name,
        visibility,
        mutability,
        is_constant,
        is_immutable,
    }
}

/// Extract state variables from a contract definition
pub fn extract_state_variables(contract_def: &ContractDefinition) -> Vec<StateVariableInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::VariableDefinition(var_def) = part {
                Some(extract_variable_info(var_def))
            } else {
                None
            }
        })
        .collect()
}

/// Extract enum information from an enum definition
pub fn extract_enum_info(enum_def: &EnumDefinition) -> EnumInfo {
    let name = enum_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let values = enum_def
        .values
        .iter()
        .filter_map(|value| value.as_ref().map(|id| id.name.clone()))
        .collect();

    EnumInfo { name, values }
}

/// Extract enums from a contract definition
pub fn extract_contract_enums(contract_def: &ContractDefinition) -> Vec<EnumInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::EnumDefinition(enum_def) = part {
                Some(extract_enum_info(enum_def))
            } else {
                None
            }
        })
        .collect()
}

/// Helper to extract type name from Expression
fn extract_type_name(type_expr: &Expression) -> String {
    match type_expr {
        Expression::Variable(ident) => ident.name.clone(),
        Expression::Type(_, ty) => format!("{:?}", ty),
        Expression::ArraySubscript(_, base, size) => {
            let base_type = extract_type_name(base);
            if let Some(size_expr) = size {
                format!("{}[{}]", base_type, extract_simple_expr(size_expr))
            } else {
                format!("{}[]", base_type)
            }
        }
        Expression::MemberAccess(_, obj, member) => {
            format!("{}.{}", extract_type_name(obj), member.name)
        }
        _ => "unknown".to_string(),
    }
}

/// Helper to extract simple expression value (for array sizes, etc.)
fn extract_simple_expr(expr: &Expression) -> String {
    match expr {
        Expression::NumberLiteral(_, val, _, _) => val.clone(),
        Expression::Variable(ident) => ident.name.clone(),
        _ => String::new(),
    }
}

/// Extract error information from an error definition
pub fn extract_error_info(error_def: &ErrorDefinition) -> ErrorInfo {
    let name = error_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let parameters = error_def
        .fields
        .iter()
        .map(|param| ErrorParameter {
            name: param.name.as_ref().map(|id| id.name.clone()),
            type_name: extract_type_name(&param.ty),
        })
        .collect();

    ErrorInfo { name, parameters }
}

/// Extract errors from a contract definition
pub fn extract_contract_errors(contract_def: &ContractDefinition) -> Vec<ErrorInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::ErrorDefinition(error_def) = part {
                Some(extract_error_info(error_def))
            } else {
                None
            }
        })
        .collect()
}

/// Extract event information from an event definition
pub fn extract_event_info(event_def: &EventDefinition) -> EventInfo {
    let name = event_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let parameters = event_def
        .fields
        .iter()
        .map(|param| EventParameter {
            name: param.name.as_ref().map(|id| id.name.clone()),
            type_name: extract_type_name(&param.ty),
            indexed: param.indexed,
        })
        .collect();

    EventInfo {
        name,
        parameters,
        anonymous: event_def.anonymous,
    }
}

/// Extract events from a contract definition
pub fn extract_contract_events(contract_def: &ContractDefinition) -> Vec<EventInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::EventDefinition(event_def) = part {
                Some(extract_event_info(event_def))
            } else {
                None
            }
        })
        .collect()
}

/// Extract struct information from a struct definition
pub fn extract_struct_info(struct_def: &StructDefinition) -> StructInfo {
    let name = struct_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let fields = struct_def
        .fields
        .iter()
        .map(|field| StructField {
            name: field.name.as_ref().map(|id| id.name.clone()),
            type_name: extract_type_name(&field.ty),
        })
        .collect();

    StructInfo { name, fields }
}

/// Extract structs from a contract definition
pub fn extract_contract_structs(contract_def: &ContractDefinition) -> Vec<StructInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::StructDefinition(struct_def) = part {
                Some(extract_struct_info(struct_def))
            } else {
                None
            }
        })
        .collect()
}

/// Extract modifier information from a modifier definition
pub fn extract_modifier_info(modifier_def: &FunctionDefinition) -> ModifierInfo {
    let name = modifier_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let parameters = modifier_def
        .params
        .iter()
        .filter_map(|(_, param_opt)| {
            param_opt.as_ref().map(|param| ModifierParameter {
                name: param.name.as_ref().map(|id| id.name.clone()),
                type_name: extract_type_name(&param.ty),
            })
        })
        .collect();

    ModifierInfo { name, parameters }
}

/// Extract modifiers from a contract definition
pub fn extract_contract_modifiers(contract_def: &ContractDefinition) -> Vec<ModifierInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::FunctionDefinition(func_def) = part {
                if matches!(func_def.ty, FunctionTy::Modifier) {
                    Some(extract_modifier_info(func_def))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Extract type definition information from a type definition
pub fn extract_type_definition_info(type_def: &TypeDefinition) -> TypeDefinitionInfo {
    let name = type_def.name.name.clone();
    let underlying_type = extract_type_name(&type_def.ty);

    TypeDefinitionInfo {
        name,
        underlying_type,
    }
}

/// Extract type definitions from a contract definition
pub fn extract_contract_type_definitions(contract_def: &ContractDefinition) -> Vec<TypeDefinitionInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::TypeDefinition(type_def) = part {
                Some(extract_type_definition_info(type_def))
            } else {
                None
            }
        })
        .collect()
}

/// Extract using directive information from a using directive
pub fn extract_using_directive_info(using: &Using) -> UsingDirectiveInfo {
    let mut library_name = None;
    let mut functions = Vec::new();

    match &using.list {
        UsingList::Library(ident_path) => {
            library_name = ident_path.identifiers.last().map(|id| id.name.clone());
        }
        UsingList::Functions(func_list) => {
            functions = func_list
                .iter()
                .filter_map(|item| item.path.identifiers.last().map(|id| id.name.clone()))
                .collect();
        }
        _ => {}
    }

    let target_type = using.ty.as_ref().map(|ty| extract_type_name(ty));

    UsingDirectiveInfo {
        library_name,
        functions,
        target_type,
    }
}

/// Extract using directives from a contract definition
pub fn extract_contract_using_directives(contract_def: &ContractDefinition) -> Vec<UsingDirectiveInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::Using(using) = part {
                Some(extract_using_directive_info(using))
            } else {
                None
            }
        })
        .collect()
}

/// Extract function information from a function definition
pub fn extract_function_info(func_def: &FunctionDefinition) -> FunctionInfo {
    // Extract function name
    let name = func_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    // Determine function type
    let function_type = match func_def.ty {
        FunctionTy::Constructor => FunctionType::Constructor,
        FunctionTy::Fallback => FunctionType::Fallback,
        FunctionTy::Receive => FunctionType::Receive,
        FunctionTy::Function | FunctionTy::Modifier => FunctionType::Function,
    };

    // Extract parameters
    let parameters: Vec<FunctionParameter> = func_def
        .params
        .iter()
        .filter_map(|(_, param_opt)| {
            param_opt.as_ref().map(|param| FunctionParameter {
                name: param.name.as_ref().map(|id| id.name.clone()),
                type_name: extract_type_name(&param.ty),
            })
        })
        .collect();

    // Extract return parameters
    let return_parameters: Vec<FunctionParameter> = func_def
        .returns
        .iter()
        .filter_map(|(_, param_opt)| {
            param_opt.as_ref().map(|param| FunctionParameter {
                name: param.name.as_ref().map(|id| id.name.clone()),
                type_name: extract_type_name(&param.ty),
            })
        })
        .collect();

    // Extract visibility from attributes
    let visibility = func_def
        .attributes
        .iter()
        .find_map(|attr| match attr {
            FunctionAttribute::Visibility(vis) => Some(match vis {
                Visibility::Public(_) => FunctionVisibility::Public,
                Visibility::Private(_) => FunctionVisibility::Private,
                Visibility::Internal(_) => FunctionVisibility::Internal,
                Visibility::External(_) => FunctionVisibility::External,
            }),
            _ => None,
        })
        .unwrap_or(FunctionVisibility::Internal); // Default visibility

    // Extract mutability from attributes
    let mutability = func_def
        .attributes
        .iter()
        .find_map(|attr| match attr {
            FunctionAttribute::Mutability(m) => Some(match m {
                Mutability::Pure(_) => FunctionMutability::Pure,
                Mutability::View(_) => FunctionMutability::View,
                Mutability::Payable(_) => FunctionMutability::Payable,
                Mutability::Constant(_) => FunctionMutability::View, // Constant is deprecated, treat as view
            }),
            _ => None,
        })
        .unwrap_or(FunctionMutability::Nonpayable); // Default mutability

    // Extract modifiers applied to this function
    let modifiers: Vec<String> = func_def
        .attributes
        .iter()
        .filter_map(|attr| {
            if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                base.name.identifiers.last().map(|id| id.name.clone())
            } else {
                None
            }
        })
        .collect();

    // Check for virtual and override flags
    let is_virtual = func_def
        .attributes
        .iter()
        .any(|attr| matches!(attr, FunctionAttribute::Virtual(_)));

    let is_override = func_def
        .attributes
        .iter()
        .any(|attr| matches!(attr, FunctionAttribute::Override(_, _)));

    FunctionInfo {
        name,
        parameters,
        return_parameters,
        visibility,
        mutability,
        function_type,
        modifiers,
        is_virtual,
        is_override,
    }
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

    // Extract function definitions (exclude modifiers as they are extracted separately)
    let function_definitions = contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::FunctionDefinition(func_def) = part {
                // Skip modifiers - they are extracted separately
                if !matches!(func_def.ty, FunctionTy::Modifier) {
                    Some(extract_function_info(func_def))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // Extract enums
    let enums = extract_contract_enums(contract_def);

    // Extract errors
    let errors = extract_contract_errors(contract_def);

    // Extract events
    let events = extract_contract_events(contract_def);

    // Extract structs
    let structs = extract_contract_structs(contract_def);

    // Extract modifiers
    let modifiers = extract_contract_modifiers(contract_def);

    // Extract type definitions
    let type_definitions = extract_contract_type_definitions(contract_def);

    // Extract using directives
    let using_directives = extract_contract_using_directives(contract_def);

    Ok(ContractInfo {
        name: name.name.clone(),
        contract_type,
        file_path: file_path.to_string_lossy().to_string(),
        direct_bases,
        inheritance_chain: Vec::new(), // Will be populated in second pass
        state_variables,
        function_definitions,
        enums,
        errors,
        events,
        structs,
        modifiers,
        type_definitions,
        using_directives,
    })
}

/// Check if a function has the virtual attribute
pub fn is_function_virtual(func_def: &FunctionDefinition) -> bool {
    func_def.attributes.iter().any(|attr| {
        matches!(attr, FunctionAttribute::Virtual(_))
    })
}

/// Check if a function is read-only (view or pure)
pub fn is_function_readonly(func_def: &FunctionDefinition) -> bool {
    func_def.attributes.iter().any(|attr| {
        matches!(attr, 
            FunctionAttribute::Mutability(Mutability::View(_)) | 
            FunctionAttribute::Mutability(Mutability::Pure(_))
        )
    })
}

/// Get the visibility of a function (if specified)
pub fn get_function_visibility(func_def: &FunctionDefinition) -> Option<&Visibility> {
    func_def.attributes.iter().find_map(|attr| {
        if let FunctionAttribute::Visibility(vis) = attr {
            Some(vis)
        } else {
            None
        }
    })
}

/// Check if an expression contains address(this) pattern
pub fn contains_address_this(expr: &Expression) -> bool {
    match expr {
        Expression::FunctionCall(_, func, args) => {
            // Check if this is address(this)
            if let Expression::Variable(var) = func.as_ref() {
                if var.name == "address" && args.len() == 1 {
                    if let Expression::Variable(arg_var) = &args[0] {
                        if arg_var.name == "this" {
                            return true;
                        }
                    }
                }
            }
            // Recursively check arguments
            args.iter().any(|arg| contains_address_this(arg))
        }
        Expression::Variable(var) if var.name == "this" => true,
        Expression::Parenthesis(_, inner) => contains_address_this(inner),
        _ => false,
    }
}

/// Heuristic check if an expression is likely an ERC20 token
pub fn is_likely_erc20_token(expr: &Expression) -> bool {
    match expr {
        Expression::Variable(var) => {
            let name_lower = var.name.to_lowercase();
            // Common ERC20 token names and stablecoins
            name_lower.contains("token") || 
            name_lower.contains("erc20") || 
            name_lower.contains("usdt") || 
            name_lower.contains("usdc") ||
            name_lower.contains("dai") ||
            name_lower.contains("weth") ||
            name_lower.contains("wbtc") ||
            name_lower.contains("busd") ||
            name_lower.contains("tusd") ||
            name_lower.contains("coin")
        }
        Expression::FunctionCall(_, func, _) => {
            // Check for ERC20/IERC20 interface casts
            if let Expression::Variable(var) = func.as_ref() {
                let name = &var.name;
                name == "ERC20" || name == "IERC20" || 
                name.contains("ERC20") || name.contains("IERC20")
            } else {
                false
            }
        }
        Expression::MemberAccess(_, base, member) => {
            let member_lower = member.name.to_lowercase();
            // Check if member suggests token or recurse on base
            (member_lower.contains("token") && !member_lower.contains("tokenid")) || 
            member_lower.contains("coin") ||
            is_likely_erc20_token(base)
        }
        Expression::ArraySubscript(_, base, _) => is_likely_erc20_token(base),
        _ => false,
    }
}

/// Heuristic check if an expression is likely an NFT (ERC721/ERC1155)
pub fn is_likely_nft(expr: &Expression) -> bool {
    match expr {
        Expression::Variable(var) => {
            let name_lower = var.name.to_lowercase();
            // Common NFT-related names
            name_lower.contains("nft") ||
            name_lower.contains("erc721") ||
            name_lower.contains("erc1155") ||
            name_lower.contains("collectible") ||
            name_lower.contains("nonfungible")
        }
        Expression::FunctionCall(_, func, _) => {
            // Check for ERC721/ERC1155 interface casts
            if let Expression::Variable(var) = func.as_ref() {
                let name = &var.name;
                name == "ERC721" || name == "IERC721" || 
                name == "ERC1155" || name == "IERC1155" ||
                name.contains("ERC721") || name.contains("IERC721") ||
                name.contains("ERC1155") || name.contains("IERC1155")
            } else {
                false
            }
        }
        Expression::MemberAccess(_, base, member) => {
            let member_lower = member.name.to_lowercase();
            // Check if member suggests NFT
            member_lower.contains("nft") || 
            member_lower.contains("collectible") ||
            is_likely_nft(base)
        }
        Expression::ArraySubscript(_, base, _) => is_likely_nft(base),
        _ => false,
    }
}

/// Check if an expression is a complex type based on AST structure (not name heuristics)
pub fn is_complex_type_structure(expr: &Expression) -> bool {
    match expr {
        // Array access like arr[i] or mapping[key] - definitely complex
        Expression::ArraySubscript(_, _, _) => true,
        
        // Multiple member accesses usually indicate struct field access
        Expression::MemberAccess(_, base, _) => {
            // Check for chained member access (e.g., order.user.name)
            matches!(base.as_ref(), Expression::MemberAccess(_, _, _))
        }
        
        _ => false,
    }
}
