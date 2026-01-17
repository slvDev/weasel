use std::collections::HashSet;

use crate::{
    models::{
        ContractInfo, ContractType, EnumInfo, ErrorInfo, ErrorParameter, EventInfo, EventParameter, FunctionInfo, FunctionMutability, FunctionParameter, FunctionType, FunctionVisibility, ImportInfo, ModifierInfo, ModifierParameter, SolidityFile, StateVariableInfo, StructField, StructInfo, TypeDefinitionInfo, TypeInfo, UsingDirectiveInfo, VariableMutability, VariableVisibility, finding::{FindingData, Location}
    },
    utils::location::loc_to_location,
};
use solang_parser::pt::{
    CatchClause, ContractDefinition, ContractPart, EnumDefinition, ErrorDefinition, EventDefinition,
    Expression, FunctionAttribute, FunctionDefinition, FunctionTy, Import, Loc, Mutability,
    PragmaDirective, Statement, StructDefinition, Type, TypeDefinition, Using, UsingList,
    VariableDeclaration, VariableDefinition, VersionComparator, VersionOp, Visibility,
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
        | Expression::Equal(_, left, right)
        | Expression::NotEqual(_, left, right)
        | Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Power(_, left, right)
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
        Statement::Return(_, expr_opt) => {
            if let Some(expr) = expr_opt {
                find_in_expression_recursive(expr, file, detector_id, predicate, findings);
            }
        }
        Statement::Emit(_, expr) => {
            find_in_expression_recursive(expr, file, detector_id, predicate, findings);
        }
        Statement::Revert(_, _, exprs) => {
            for expr in exprs {
                find_in_expression_recursive(expr, file, detector_id, predicate, findings);
            }
        }
        Statement::Try(_, expr, _, catch_clauses) => {
            find_in_expression_recursive(expr, file, detector_id, predicate, findings);
            for clause in catch_clauses {
                let stmt = match clause {
                    CatchClause::Simple(_, _, stmt) => stmt,
                    CatchClause::Named(_, _, _, stmt) => stmt,
                };
                find_in_statement_recursive(stmt, file, detector_id, predicate, findings);
            }
        }
        _ => {}
    }
}

/// Find statement types matching a predicate (e.g., Return, Revert statements)
/// Returns Vec<FindingData> for matching statements
pub fn find_statement_types<F>(
    stmt: &Statement,
    file: &SolidityFile,
    detector_id: &'static str,
    mut predicate: F,
) -> Vec<FindingData>
where
    F: FnMut(&Statement) -> bool,
{
    let mut findings = Vec::new();
    find_statement_types_recursive(stmt, file, detector_id, &mut predicate, &mut findings);
    findings
}

fn find_statement_types_recursive<F>(
    stmt: &Statement,
    file: &SolidityFile,
    detector_id: &'static str,
    predicate: &mut F,
    findings: &mut Vec<FindingData>,
) where
    F: FnMut(&Statement) -> bool,
{
    // Check current statement against predicate
    if predicate(stmt) {
        if let Some(loc) = get_statement_location(stmt) {
            findings.push(FindingData {
                detector_id,
                location: loc_to_location(&loc, file),
            });
        }
    }

    // Recursively check child statements
    match stmt {
        Statement::Block { statements, .. } => {
            for inner_stmt in statements {
                find_statement_types_recursive(inner_stmt, file, detector_id, predicate, findings);
            }
        }
        Statement::If(_, _, then_stmt, else_stmt_opt) => {
            find_statement_types_recursive(then_stmt, file, detector_id, predicate, findings);
            if let Some(else_stmt) = else_stmt_opt {
                find_statement_types_recursive(else_stmt, file, detector_id, predicate, findings);
            }
        }
        Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
            find_statement_types_recursive(body, file, detector_id, predicate, findings);
        }
        Statement::For(_, init_opt, _, _, body_opt) => {
            if let Some(init) = init_opt {
                find_statement_types_recursive(init, file, detector_id, predicate, findings);
            }
            if let Some(body) = body_opt {
                find_statement_types_recursive(body, file, detector_id, predicate, findings);
            }
        }
        Statement::Try(_, _, returns_opt, catch_clauses) => {
            if let Some((_, returns_block)) = returns_opt {
                find_statement_types_recursive(returns_block, file, detector_id, predicate, findings);
            }
            for clause in catch_clauses {
                let clause_stmt = match clause {
                    CatchClause::Simple(_, _, s) => s,
                    CatchClause::Named(_, _, _, s) => s,
                };
                find_statement_types_recursive(clause_stmt, file, detector_id, predicate, findings);
            }
        }
        _ => {}
    }
}

/// Helper function to get location from any statement
fn get_statement_location(stmt: &Statement) -> Option<Loc> {
    match stmt {
        Statement::Block { loc, .. }
        | Statement::Assembly { loc, .. }
        | Statement::Args(loc, _)
        | Statement::If(loc, _, _, _)
        | Statement::While(loc, _, _)
        | Statement::Expression(loc, _)
        | Statement::VariableDefinition(loc, _, _)
        | Statement::For(loc, _, _, _, _)
        | Statement::DoWhile(loc, _, _)
        | Statement::Continue(loc)
        | Statement::Break(loc)
        | Statement::Return(loc, _)
        | Statement::Revert(loc, _, _)
        | Statement::RevertNamedArgs(loc, _, _)
        | Statement::Emit(loc, _)
        | Statement::Try(loc, _, _, _)
        | Statement::Error(loc) => Some(*loc),
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
        | Expression::Power(loc, _, _)
        | Expression::Assign(loc, _, _)
        | Expression::Parenthesis(loc, _)
        | Expression::Negate(loc, _)
        | Expression::FunctionCall(loc, _, _)
        | Expression::NumberLiteral(loc, _, _, _)
        | Expression::BoolLiteral(loc, _) => Some(loc.clone()),
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

/// Collect local variable declaration names from a statement
pub fn collect_local_declarations(stmt: &Statement, local_vars: &mut HashSet<String>) {
    collect_local_variables(stmt, &mut |decl| {
        if let Some(name) = &decl.name {
            local_vars.insert(name.name.clone());
        }
    });
}

/// The callback receives the full VariableDeclaration and can extract any needed info.
pub fn collect_local_variables<F>(stmt: &Statement, callback: &mut F)
where
    F: FnMut(&VariableDeclaration),
{
    match stmt {
        Statement::VariableDefinition(_, decl, _) => {
            callback(decl);
        }
        Statement::Block { statements, .. } => {
            for s in statements {
                collect_local_variables(s, callback);
            }
        }
        Statement::If(_, _, then_stmt, else_stmt) => {
            collect_local_variables(then_stmt, callback);
            if let Some(else_s) = else_stmt {
                collect_local_variables(else_s, callback);
            }
        }
        Statement::For(_, init, _, _, body_opt) => {
            if let Some(init_stmt) = init {
                collect_local_variables(init_stmt, callback);
            }
            if let Some(body) = body_opt {
                collect_local_variables(body, callback);
            }
        }
        Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
            collect_local_variables(body, callback);
        }
        _ => {}
    }
}

/// Collect all function call names from a statement
pub fn collect_function_calls(stmt: &Statement, calls: &mut HashSet<String>) {
    match stmt {
        Statement::Block { statements, .. } => {
            for s in statements {
                collect_function_calls(s, calls);
            }
        }
        Statement::Expression(_, expr)
        | Statement::Return(_, Some(expr))
        | Statement::Emit(_, expr) => {
            collect_function_calls_from_expr(expr, calls);
        }
        Statement::VariableDefinition(_, _, Some(expr)) => {
            collect_function_calls_from_expr(expr, calls);
        }
        Statement::If(_, cond, then_stmt, else_stmt) => {
            collect_function_calls_from_expr(cond, calls);
            collect_function_calls(then_stmt, calls);
            if let Some(else_s) = else_stmt {
                collect_function_calls(else_s, calls);
            }
        }
        Statement::While(_, cond, body) | Statement::DoWhile(_, body, cond) => {
            collect_function_calls_from_expr(cond, calls);
            collect_function_calls(body, calls);
        }
        Statement::For(_, init, cond, update, body) => {
            if let Some(init_stmt) = init {
                collect_function_calls(init_stmt, calls);
            }
            if let Some(cond_expr) = cond {
                collect_function_calls_from_expr(cond_expr, calls);
            }
            if let Some(update_expr) = update {
                collect_function_calls_from_expr(update_expr, calls);
            }
            if let Some(body_stmt) = body {
                collect_function_calls(body_stmt, calls);
            }
        }
        _ => {}
    }
}

/// Collect function call names from an expression
pub fn collect_function_calls_from_expr(expr: &Expression, calls: &mut HashSet<String>) {
    match expr {
        Expression::FunctionCall(_, func_expr, args) => {
            // Collect the function name if it's a simple identifier
            if let Expression::Variable(ident) = func_expr.as_ref() {
                calls.insert(ident.name.clone());
            }
            // Recurse into the function expression and arguments
            collect_function_calls_from_expr(func_expr, calls);
            for arg in args {
                collect_function_calls_from_expr(arg, calls);
            }
        }
        // Unary operations
        Expression::MemberAccess(_, expr, _)
        | Expression::Not(_, expr)
        | Expression::BitwiseNot(_, expr)
        | Expression::UnaryPlus(_, expr)
        | Expression::PreIncrement(_, expr)
        | Expression::PreDecrement(_, expr)
        | Expression::PostIncrement(_, expr)
        | Expression::PostDecrement(_, expr) => {
            collect_function_calls_from_expr(expr, calls);
        }
        Expression::Negate(_, expr) => {
            collect_function_calls_from_expr(expr, calls);
        }
        // Binary operations
        Expression::Add(_, l, r)
        | Expression::Subtract(_, l, r)
        | Expression::Multiply(_, l, r)
        | Expression::Divide(_, l, r)
        | Expression::Modulo(_, l, r)
        | Expression::Power(_, l, r)
        | Expression::ShiftLeft(_, l, r)
        | Expression::ShiftRight(_, l, r)
        | Expression::BitwiseAnd(_, l, r)
        | Expression::BitwiseOr(_, l, r)
        | Expression::BitwiseXor(_, l, r)
        | Expression::Equal(_, l, r)
        | Expression::NotEqual(_, l, r)
        | Expression::Less(_, l, r)
        | Expression::LessEqual(_, l, r)
        | Expression::More(_, l, r)
        | Expression::MoreEqual(_, l, r)
        | Expression::And(_, l, r)
        | Expression::Or(_, l, r)
        | Expression::Assign(_, l, r)
        | Expression::AssignAdd(_, l, r)
        | Expression::AssignSubtract(_, l, r)
        | Expression::AssignMultiply(_, l, r)
        | Expression::AssignDivide(_, l, r)
        | Expression::AssignModulo(_, l, r)
        | Expression::AssignShiftLeft(_, l, r)
        | Expression::AssignShiftRight(_, l, r)
        | Expression::AssignOr(_, l, r)
        | Expression::AssignAnd(_, l, r)
        | Expression::AssignXor(_, l, r) => {
            collect_function_calls_from_expr(l, calls);
            collect_function_calls_from_expr(r, calls);
        }
        Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            collect_function_calls_from_expr(cond, calls);
            collect_function_calls_from_expr(then_expr, calls);
            collect_function_calls_from_expr(else_expr, calls);
        }
        Expression::ArraySubscript(_, base, index) => {
            collect_function_calls_from_expr(base, calls);
            if let Some(idx) = index {
                collect_function_calls_from_expr(idx, calls);
            }
        }
        // Literals and identifiers don't contain calls
        _ => {}
    }
}

/// Process a single import directive
pub fn process_import_directive(import: &Import, file: &SolidityFile) -> Result<ImportInfo, String> {
    use solang_parser::pt::ImportPath;

    // Extract import path, symbols, and location based on import type
    let (path_literal, symbols, import_loc) = match import {
        Import::Plain(literal, loc) => {
            // Simple import without specific symbols: import "hardhat/console.sol";
            (Some(literal), Vec::new(), loc)
        }
        Import::GlobalSymbol(literal, symbol, loc) => {
            // Import with global symbol: import <0> as <1>;
            let symbols = vec![symbol.name.clone()];
            (Some(literal), symbols, loc)
        }
        Import::Rename(literal, symbol_list, loc) => {
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
            (Some(literal), symbols, loc)
        }
    };

    // Extract actual import path string
    let import_path = if let Some(ImportPath::Filename(filepath)) = path_literal {
        filepath.string.clone()
    } else {
        return Err("Invalid import path format".to_string());
    };

    let loc = loc_to_location(import_loc, file);

    Ok(ImportInfo {
        loc,
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

/// Extract variable information from a variable definition
pub fn extract_variable_info(var_def: &VariableDefinition, file: &SolidityFile) -> StateVariableInfo {
    let loc = loc_to_location(&var_def.loc, file);

    let name = var_def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_else(|| "Unnamed".to_string());

    let type_info = TypeInfo::from_expression(&var_def.ty);

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
        loc,
        name,
        type_info,
        visibility,
        mutability,
        is_constant,
        is_immutable,
    }
}

/// Extract state variables from a contract definition
pub fn extract_state_variables(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<StateVariableInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::VariableDefinition(var_def) = part {
                Some(extract_variable_info(var_def, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract enum information from an enum definition
pub fn extract_enum_info(enum_def: &EnumDefinition, file: &SolidityFile) -> EnumInfo {
    let loc = loc_to_location(&enum_def.loc, file);

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

    EnumInfo {
        loc,
        name,
        values,
    }
}

/// Extract enums from a contract definition
pub fn extract_contract_enums(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<EnumInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::EnumDefinition(enum_def) = part {
                Some(extract_enum_info(enum_def, file))
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
pub fn extract_error_info(error_def: &ErrorDefinition, file: &SolidityFile) -> ErrorInfo {
    let loc = loc_to_location(&error_def.loc, file);

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

    ErrorInfo {
        loc,
        name,
        parameters,
    }
}

/// Extract errors from a contract definition
pub fn extract_contract_errors(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<ErrorInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::ErrorDefinition(error_def) = part {
                Some(extract_error_info(error_def, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract event information from an event definition
pub fn extract_event_info(event_def: &EventDefinition, file: &SolidityFile) -> EventInfo {
    let loc = loc_to_location(&event_def.loc, file);

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
        loc,
        name,
        parameters,
        anonymous: event_def.anonymous,
    }
}

/// Extract events from a contract definition
pub fn extract_contract_events(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<EventInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::EventDefinition(event_def) = part {
                Some(extract_event_info(event_def, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract struct information from a struct definition
pub fn extract_struct_info(struct_def: &StructDefinition, file: &SolidityFile) -> StructInfo {
    let loc = loc_to_location(&struct_def.loc, file);

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

    StructInfo {
        loc,
        name,
        fields,
    }
}

/// Extract structs from a contract definition
pub fn extract_contract_structs(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<StructInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::StructDefinition(struct_def) = part {
                Some(extract_struct_info(struct_def, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract modifier information from a modifier definition
pub fn extract_modifier_info(modifier_def: &FunctionDefinition, file: &SolidityFile) -> ModifierInfo {
    let loc = loc_to_location(&modifier_def.loc, file);

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

    ModifierInfo {
        loc,
        name,
        parameters,
    }
}

/// Extract modifiers from a contract definition
pub fn extract_contract_modifiers(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<ModifierInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::FunctionDefinition(func_def) = part {
                if matches!(func_def.ty, FunctionTy::Modifier) {
                    Some(extract_modifier_info(func_def, file))
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
pub fn extract_type_definition_info(type_def: &TypeDefinition, file: &SolidityFile) -> TypeDefinitionInfo {
    let loc = loc_to_location(&type_def.loc, file);
    let name = type_def.name.name.clone();
    let underlying_type = extract_type_name(&type_def.ty);

    TypeDefinitionInfo {
        loc,
        name,
        underlying_type,
    }
}

/// Extract type definitions from a contract definition
pub fn extract_contract_type_definitions(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<TypeDefinitionInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::TypeDefinition(type_def) = part {
                Some(extract_type_definition_info(type_def, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract using directive information from a using directive
pub fn extract_using_directive_info(using: &Using, file: &SolidityFile) -> UsingDirectiveInfo {
    let loc = loc_to_location(&using.loc, file);
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
        loc,
        library_name,
        functions,
        target_type,
    }
}

/// Extract using directives from a contract definition
pub fn extract_contract_using_directives(contract_def: &ContractDefinition, file: &SolidityFile) -> Vec<UsingDirectiveInfo> {
    contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::Using(using) = part {
                Some(extract_using_directive_info(using, file))
            } else {
                None
            }
        })
        .collect()
}

/// Extract function information from a function definition
pub fn extract_function_info(func_def: &FunctionDefinition, file: &SolidityFile) -> FunctionInfo {
    let loc = loc_to_location(&func_def.loc, file);

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
        loc,
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

/// Get pre-extracted ContractInfo for a ContractDefinition
pub fn get_contract_info<'a>(
    contract_def: &ContractDefinition,
    file: &'a SolidityFile,
) -> Option<&'a ContractInfo> {
    let name = contract_def.name.as_ref()?.name.as_str();
    file.contract_definitions.iter().find(|c| c.name == name)
}

/// Extract information from a single contract definition
pub fn extract_contract_info(
    contract_def: &ContractDefinition,
    file: &SolidityFile,
) -> Result<ContractInfo, String> {
    let loc = loc_to_location(&contract_def.loc, file);
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
    let state_variables = extract_state_variables(contract_def, file);

    // Extract function definitions (exclude modifiers as they are extracted separately)
    let function_definitions = contract_def
        .parts
        .iter()
        .filter_map(|part| {
            if let ContractPart::FunctionDefinition(func_def) = part {
                // Skip modifiers - they are extracted separately
                if !matches!(func_def.ty, FunctionTy::Modifier) {
                    Some(extract_function_info(func_def, file))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // Extract enums
    let enums = extract_contract_enums(contract_def, file);

    // Extract errors
    let errors = extract_contract_errors(contract_def, file);

    // Extract events
    let events = extract_contract_events(contract_def, file);

    // Extract structs
    let structs = extract_contract_structs(contract_def, file);

    // Extract modifiers
    let modifiers = extract_contract_modifiers(contract_def, file);

    // Extract type definitions
    let type_definitions = extract_contract_type_definitions(contract_def, file);

    // Extract using directives
    let using_directives = extract_contract_using_directives(contract_def, file);

    Ok(ContractInfo {
        loc,
        name: name.name.clone(),
        contract_type,
        file_path: file.path.to_string_lossy().to_string(),
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
