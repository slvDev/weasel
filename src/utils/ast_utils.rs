use crate::{
    models::{finding::Location, SolidityFile},
    utils::location::loc_to_location,
};
use solang_parser::pt::{Expression, Loc, Statement, Type};

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
