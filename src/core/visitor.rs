use crate::models::{finding::FindingData, SolidityFile};
use solang_parser::pt::{
    ContractDefinition, ContractPart, Expression, FunctionDefinition, SourceUnit, SourceUnitPart,
    Statement, VariableDefinition,
};
pub struct ASTVisitor {
    source_unit_callbacks:
        Vec<Box<dyn Fn(&SourceUnit, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    source_unit_part_callbacks:
        Vec<Box<dyn Fn(&SourceUnitPart, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    contract_callbacks:
        Vec<Box<dyn Fn(&ContractDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    contract_part_callbacks:
        Vec<Box<dyn Fn(&ContractPart, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    function_callbacks:
        Vec<Box<dyn Fn(&FunctionDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    variable_callbacks:
        Vec<Box<dyn Fn(&VariableDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    expression_callbacks:
        Vec<Box<dyn Fn(&Expression, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
    statement_callbacks:
        Vec<Box<dyn Fn(&Statement, &SolidityFile) -> Vec<FindingData> + Send + Sync>>,
}

impl ASTVisitor {
    pub fn new() -> Self {
        Self {
            source_unit_callbacks: Vec::new(),
            source_unit_part_callbacks: Vec::new(),
            contract_callbacks: Vec::new(),
            contract_part_callbacks: Vec::new(),
            function_callbacks: Vec::new(),
            variable_callbacks: Vec::new(),
            expression_callbacks: Vec::new(),
            statement_callbacks: Vec::new(),
        }
    }

    #[allow(dead_code)] // Dont use this for now.
    pub fn on_source_unit<F>(&mut self, callback: F)
    where
        F: Fn(&SourceUnit, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.source_unit_callbacks.push(Box::new(callback));
    }

    pub fn on_source_unit_part<F>(&mut self, callback: F)
    where
        F: Fn(&SourceUnitPart, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.source_unit_part_callbacks.push(Box::new(callback));
    }

    pub fn on_contract<F>(&mut self, callback: F)
    where
        F: Fn(&ContractDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.contract_callbacks.push(Box::new(callback));
    }

    pub fn on_contract_part<F>(&mut self, callback: F)
    where
        F: Fn(&ContractPart, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.contract_part_callbacks.push(Box::new(callback));
    }

    pub fn on_function<F>(&mut self, callback: F)
    where
        F: Fn(&FunctionDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.function_callbacks.push(Box::new(callback));
    }

    pub fn on_variable<F>(&mut self, callback: F)
    where
        F: Fn(&VariableDefinition, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.variable_callbacks.push(Box::new(callback));
    }

    pub fn on_expression<F>(&mut self, callback: F)
    where
        F: Fn(&Expression, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.expression_callbacks.push(Box::new(callback));
    }

    pub fn on_statement<F>(&mut self, callback: F)
    where
        F: Fn(&Statement, &SolidityFile) -> Vec<FindingData> + Send + Sync + 'static,
    {
        self.statement_callbacks.push(Box::new(callback));
    }

    pub fn visit_source_unit(
        &self,
        source_unit: &SourceUnit,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.source_unit_callbacks {
            all_findings.extend(callback(source_unit, file));
        }

        for part in &source_unit.0 {
            for callback in &self.source_unit_part_callbacks {
                all_findings.extend(callback(part, file));
            }

            match part {
                SourceUnitPart::ContractDefinition(contract) => {
                    self.visit_contract(contract, all_findings, file);
                }
                SourceUnitPart::FunctionDefinition(function) => {
                    self.visit_function(function, all_findings, file);
                }
                SourceUnitPart::VariableDefinition(variable) => {
                    self.visit_variable(variable, all_findings, file);
                }
                SourceUnitPart::TypeDefinition(type_definition) => {
                    self.visit_expression(&type_definition.ty, all_findings, file);
                }
                SourceUnitPart::StructDefinition(struct_definition) => {
                    for field in &struct_definition.fields {
                        self.visit_expression(&field.ty, all_findings, file);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn visit_contract(
        &self,
        contract: &ContractDefinition,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.contract_callbacks {
            all_findings.extend(callback(contract, file));
        }

        for base in &contract.base {
            if let Some(args) = &base.args {
                for arg in args {
                    self.visit_expression(arg, all_findings, file);
                }
            }
        }

        for part in &contract.parts {
            for callback in &self.contract_part_callbacks {
                all_findings.extend(callback(part, file));
            }
            match part {
                ContractPart::FunctionDefinition(function) => {
                    self.visit_function(function, all_findings, file);
                }
                ContractPart::VariableDefinition(variable) => {
                    self.visit_variable(variable, all_findings, file);
                }
                ContractPart::TypeDefinition(type_definition) => {
                    self.visit_expression(&type_definition.ty, all_findings, file);
                }
                ContractPart::StructDefinition(struct_definition) => {
                    for field in &struct_definition.fields {
                        self.visit_expression(&field.ty, all_findings, file);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn visit_function(
        &self,
        function: &FunctionDefinition,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.function_callbacks {
            all_findings.extend(callback(function, file));
        }
        for (_, param_opt) in &function.params {
            if let Some(param) = param_opt {
                self.visit_expression(&param.ty, all_findings, file);
            }
        }

        for (_, param_opt) in &function.returns {
            if let Some(param) = param_opt {
                self.visit_expression(&param.ty, all_findings, file);
            }
        }

        if let Some(body) = &function.body {
            self.visit_statement(body, all_findings, file);
        }
    }

    pub fn visit_variable(
        &self,
        variable: &VariableDefinition,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.variable_callbacks {
            all_findings.extend(callback(variable, file));
        }

        self.visit_expression(&variable.ty, all_findings, file);

        if let Some(initializer) = &variable.initializer {
            self.visit_expression(initializer, all_findings, file);
        }
    }

    pub fn visit_expression(
        &self,
        expression: &Expression,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.expression_callbacks {
            all_findings.extend(callback(expression, file));
        }

        match expression {
            // Unary operations
            Expression::PostIncrement(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::PostDecrement(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::PreIncrement(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::PreDecrement(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::UnaryPlus(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::Negate(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::Not(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::BitwiseNot(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::Delete(_, expr) => self.visit_expression(expr, all_findings, file),
            Expression::New(_, expr) => self.visit_expression(expr, all_findings, file),

            Expression::Power(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Multiply(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Divide(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Modulo(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Add(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Subtract(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::ShiftLeft(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::ShiftRight(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::BitwiseAnd(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::BitwiseXor(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::BitwiseOr(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Less(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::More(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::LessEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::MoreEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Equal(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::NotEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::And(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::Or(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }

            Expression::Assign(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignOr(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignAnd(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignXor(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignShiftLeft(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignShiftRight(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignAdd(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignSubtract(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignMultiply(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignDivide(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }
            Expression::AssignModulo(_, left, right) => {
                self.visit_expression(left, all_findings, file);
                self.visit_expression(right, all_findings, file);
            }

            Expression::ConditionalOperator(_, condition, true_branch, false_branch) => {
                self.visit_expression(condition, all_findings, file);
                self.visit_expression(true_branch, all_findings, file);
                self.visit_expression(false_branch, all_findings, file);
            }

            Expression::ArraySubscript(_, array, index_opt) => {
                self.visit_expression(array, all_findings, file);
                if let Some(index) = index_opt {
                    self.visit_expression(index, all_findings, file);
                }
            }
            Expression::ArraySlice(_, array, start_opt, end_opt) => {
                self.visit_expression(array, all_findings, file);
                if let Some(start) = start_opt {
                    self.visit_expression(start, all_findings, file);
                }
                if let Some(end) = end_opt {
                    self.visit_expression(end, all_findings, file);
                }
            }
            Expression::ArrayLiteral(_, elements) => {
                for element in elements {
                    self.visit_expression(element, all_findings, file);
                }
            }

            Expression::FunctionCall(_, function, args) => {
                self.visit_expression(function, all_findings, file);
                for arg in args {
                    self.visit_expression(arg, all_findings, file);
                }
            }
            Expression::FunctionCallBlock(_, function, block) => {
                self.visit_expression(function, all_findings, file);
                self.visit_statement(block, all_findings, file);
            }
            Expression::NamedFunctionCall(_, function, args) => {
                self.visit_expression(function, all_findings, file);
                for arg in args {
                    self.visit_expression(&arg.expr, all_findings, file);
                }
            }

            Expression::MemberAccess(_, object, _) => {
                self.visit_expression(object, all_findings, file);
            }

            Expression::Parenthesis(_, expr) => {
                self.visit_expression(expr, all_findings, file);
            }
            Expression::List(_, params) => {
                for (_, param_opt) in params {
                    if let Some(_) = param_opt {
                        // Parameters don't need to be visited as they don't have expressions
                    }
                }
            }

            Expression::BoolLiteral(_, _) => {}
            Expression::NumberLiteral(_, _, _, _) => {}
            Expression::RationalNumberLiteral(_, _, _, _, _) => {}
            Expression::HexNumberLiteral(_, _, _) => {}
            Expression::StringLiteral(_) => {}
            Expression::HexLiteral(_) => {}
            Expression::AddressLiteral(_, _) => {}
            Expression::Variable(_) => {}
            Expression::Type(_, _) => {}
        }
    }

    pub fn visit_statement(
        &self,
        statement: &Statement,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
    ) {
        for callback in &self.statement_callbacks {
            all_findings.extend(callback(statement, file));
        }

        match statement {
            Statement::Block {
                loc: _,
                unchecked: _,
                statements,
            } => {
                for stmt in statements {
                    self.visit_statement(stmt, all_findings, file);
                }
            }
            Statement::If(_, condition, true_branch, false_branch_opt) => {
                self.visit_expression(condition, all_findings, file);
                self.visit_statement(true_branch, all_findings, file);
                if let Some(false_branch) = false_branch_opt {
                    self.visit_statement(false_branch, all_findings, file);
                }
            }
            Statement::While(_, condition, body) => {
                self.visit_expression(condition, all_findings, file);
                self.visit_statement(body, all_findings, file);
            }
            Statement::DoWhile(_, body, condition) => {
                self.visit_statement(body, all_findings, file);
                self.visit_expression(condition, all_findings, file);
            }
            Statement::For(_, init_opt, condition_opt, update_opt, body_opt) => {
                if let Some(init) = init_opt {
                    self.visit_statement(init, all_findings, file);
                }
                if let Some(condition) = condition_opt {
                    self.visit_expression(condition, all_findings, file);
                }
                if let Some(update) = update_opt {
                    self.visit_expression(update, all_findings, file);
                }
                if let Some(body) = body_opt {
                    self.visit_statement(body, all_findings, file);
                }
            }
            Statement::Expression(_, expr) => {
                self.visit_expression(expr, all_findings, file);
            }
            Statement::VariableDefinition(_, variable_decl, init_expr_opt) => {
                self.visit_expression(&variable_decl.ty, all_findings, file);
                if let Some(init_expr) = init_expr_opt {
                    self.visit_expression(init_expr, all_findings, file);
                }
            }
            Statement::Return(_, expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr, all_findings, file);
                }
            }
            Statement::Emit(_, expr) => {
                self.visit_expression(expr, all_findings, file);
            }
            Statement::Revert(_, _, args) => {
                for arg in args {
                    self.visit_expression(arg, all_findings, file);
                }
            }
            Statement::RevertNamedArgs(_, _, args) => {
                for arg in args {
                    self.visit_expression(&arg.expr, all_findings, file);
                }
            }
            Statement::Try(_, expr, returns_opt, catch_clauses) => {
                self.visit_expression(expr, all_findings, file);

                if let Some((_, returns_block)) = returns_opt {
                    self.visit_statement(returns_block, all_findings, file);
                }

                for catch_clause in catch_clauses {
                    match catch_clause {
                        solang_parser::pt::CatchClause::Simple(_, _, stmt) => {
                            self.visit_statement(stmt, all_findings, file);
                        }
                        solang_parser::pt::CatchClause::Named(_, _, _, stmt) => {
                            self.visit_statement(stmt, all_findings, file);
                        }
                    }
                }
            }
            Statement::Continue(_) => {}
            Statement::Break(_) => {}
            Statement::Error(_) => {}
            Statement::Assembly { .. } => {}
            Statement::Args(_, args) => {
                for arg in args {
                    self.visit_expression(&arg.expr, all_findings, file);
                }
            }
        }
    }

    // pub fn traverse(&self, files: &[SolidityFile]) -> Vec<FindingData> {
    //     let mut all_findings: Vec<FindingData> = Vec::new();
    //     for file in files {
    //         if let Some(source_unit) = &file.source_unit {
    //             self.visit_source_unit(source_unit, &mut all_findings, file);
    //         }
    //     }
    //     all_findings
    // }

    pub fn traverse(&self, file: &SolidityFile) -> Vec<FindingData> {
        let mut all_findings: Vec<FindingData> = Vec::new();
        if let Some(source_unit) = &file.source_unit {
            self.visit_source_unit(&source_unit, &mut all_findings, file);
        }
        all_findings
    }
}
