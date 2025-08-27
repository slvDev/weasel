use crate::core::context::AnalysisContext;
use crate::models::{finding::FindingData, SolidityFile};
use solang_parser::pt::{
    ContractDefinition, ContractPart, Expression, FunctionDefinition, SourceUnit, SourceUnitPart,
    Statement, VariableDefinition,
};
pub struct ASTVisitor {
    source_unit_callbacks: Vec<
        Box<dyn Fn(&SourceUnit, &SolidityFile, &AnalysisContext) -> Vec<FindingData> + Send + Sync>,
    >,
    source_unit_part_callbacks: Vec<
        Box<
            dyn Fn(&SourceUnitPart, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
                + Send
                + Sync,
        >,
    >,
    contract_callbacks: Vec<
        Box<
            dyn Fn(&ContractDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
                + Send
                + Sync,
        >,
    >,
    contract_part_callbacks: Vec<
        Box<
            dyn Fn(&ContractPart, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
                + Send
                + Sync,
        >,
    >,
    function_callbacks: Vec<
        Box<
            dyn Fn(&FunctionDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
                + Send
                + Sync,
        >,
    >,
    variable_callbacks: Vec<
        Box<
            dyn Fn(&VariableDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
                + Send
                + Sync,
        >,
    >,
    expression_callbacks: Vec<
        Box<dyn Fn(&Expression, &SolidityFile, &AnalysisContext) -> Vec<FindingData> + Send + Sync>,
    >,
    statement_callbacks: Vec<
        Box<dyn Fn(&Statement, &SolidityFile, &AnalysisContext) -> Vec<FindingData> + Send + Sync>,
    >,
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
        F: Fn(&SourceUnit, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.source_unit_callbacks.push(Box::new(callback));
    }

    pub fn on_source_unit_part<F>(&mut self, callback: F)
    where
        F: Fn(&SourceUnitPart, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.source_unit_part_callbacks.push(Box::new(callback));
    }

    pub fn on_contract<F>(&mut self, callback: F)
    where
        F: Fn(&ContractDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.contract_callbacks.push(Box::new(callback));
    }

    pub fn on_contract_part<F>(&mut self, callback: F)
    where
        F: Fn(&ContractPart, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.contract_part_callbacks.push(Box::new(callback));
    }

    pub fn on_function<F>(&mut self, callback: F)
    where
        F: Fn(&FunctionDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.function_callbacks.push(Box::new(callback));
    }

    pub fn on_variable<F>(&mut self, callback: F)
    where
        F: Fn(&VariableDefinition, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.variable_callbacks.push(Box::new(callback));
    }

    pub fn on_expression<F>(&mut self, callback: F)
    where
        F: Fn(&Expression, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.expression_callbacks.push(Box::new(callback));
    }

    pub fn on_statement<F>(&mut self, callback: F)
    where
        F: Fn(&Statement, &SolidityFile, &AnalysisContext) -> Vec<FindingData>
            + Send
            + Sync
            + 'static,
    {
        self.statement_callbacks.push(Box::new(callback));
    }

    pub fn visit_source_unit(
        &self,
        source_unit: &SourceUnit,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
        context: &AnalysisContext,
    ) {
        for callback in &self.source_unit_callbacks {
            all_findings.extend(callback(source_unit, file, context));
        }

        for part in &source_unit.0 {
            for callback in &self.source_unit_part_callbacks {
                all_findings.extend(callback(part, file, context));
            }

            match part {
                SourceUnitPart::ContractDefinition(contract) => {
                    self.visit_contract(contract, all_findings, file, context);
                }
                SourceUnitPart::FunctionDefinition(function) => {
                    self.visit_function(function, all_findings, file, context);
                }
                SourceUnitPart::VariableDefinition(variable) => {
                    self.visit_variable(variable, all_findings, file, context);
                }
                SourceUnitPart::TypeDefinition(type_definition) => {
                    self.visit_expression(&type_definition.ty, all_findings, file, context);
                }
                SourceUnitPart::StructDefinition(struct_definition) => {
                    for field in &struct_definition.fields {
                        self.visit_expression(&field.ty, all_findings, file, context);
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
        context: &AnalysisContext,
    ) {
        for callback in &self.contract_callbacks {
            all_findings.extend(callback(contract, file, context));
        }

        for base in &contract.base {
            if let Some(args) = &base.args {
                for arg in args {
                    self.visit_expression(arg, all_findings, file, context);
                }
            }
        }

        for part in &contract.parts {
            for callback in &self.contract_part_callbacks {
                all_findings.extend(callback(part, file, context));
            }
            match part {
                ContractPart::FunctionDefinition(function) => {
                    self.visit_function(function, all_findings, file, context);
                }
                ContractPart::VariableDefinition(variable) => {
                    self.visit_variable(variable, all_findings, file, context);
                }
                ContractPart::TypeDefinition(type_definition) => {
                    self.visit_expression(&type_definition.ty, all_findings, file, context);
                }
                ContractPart::StructDefinition(struct_definition) => {
                    for field in &struct_definition.fields {
                        self.visit_expression(&field.ty, all_findings, file, context);
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
        context: &AnalysisContext,
    ) {
        for callback in &self.function_callbacks {
            all_findings.extend(callback(function, file, context));
        }
        for (_, param_opt) in &function.params {
            if let Some(param) = param_opt {
                self.visit_expression(&param.ty, all_findings, file, context);
            }
        }

        for (_, param_opt) in &function.returns {
            if let Some(param) = param_opt {
                self.visit_expression(&param.ty, all_findings, file, context);
            }
        }

        if let Some(body) = &function.body {
            self.visit_statement(body, all_findings, file, context);
        }
    }

    pub fn visit_variable(
        &self,
        variable: &VariableDefinition,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
        context: &AnalysisContext,
    ) {
        for callback in &self.variable_callbacks {
            all_findings.extend(callback(variable, file, context));
        }

        self.visit_expression(&variable.ty, all_findings, file, context);

        if let Some(initializer) = &variable.initializer {
            self.visit_expression(initializer, all_findings, file, context);
        }
    }

    pub fn visit_expression(
        &self,
        expression: &Expression,
        all_findings: &mut Vec<FindingData>,
        file: &SolidityFile,
        context: &AnalysisContext,
    ) {
        for callback in &self.expression_callbacks {
            all_findings.extend(callback(expression, file, context));
        }

        match expression {
            // Unary operations
            Expression::PostIncrement(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::PostDecrement(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::PreIncrement(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::PreDecrement(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::UnaryPlus(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::Negate(_, expr) => self.visit_expression(expr, all_findings, file, context),
            Expression::Not(_, expr) => self.visit_expression(expr, all_findings, file, context),
            Expression::BitwiseNot(_, expr) => {
                self.visit_expression(expr, all_findings, file, context)
            }
            Expression::Delete(_, expr) => self.visit_expression(expr, all_findings, file, context),
            Expression::New(_, expr) => self.visit_expression(expr, all_findings, file, context),

            Expression::Power(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Multiply(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Divide(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Modulo(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Add(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Subtract(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::ShiftLeft(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::ShiftRight(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::BitwiseAnd(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::BitwiseXor(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::BitwiseOr(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Less(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::More(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::LessEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::MoreEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Equal(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::NotEqual(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::And(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::Or(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }

            Expression::Assign(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignOr(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignAnd(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignXor(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignShiftLeft(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignShiftRight(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignAdd(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignSubtract(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignMultiply(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignDivide(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }
            Expression::AssignModulo(_, left, right) => {
                self.visit_expression(left, all_findings, file, context);
                self.visit_expression(right, all_findings, file, context);
            }

            Expression::ConditionalOperator(_, condition, true_branch, false_branch) => {
                self.visit_expression(condition, all_findings, file, context);
                self.visit_expression(true_branch, all_findings, file, context);
                self.visit_expression(false_branch, all_findings, file, context);
            }

            Expression::ArraySubscript(_, array, index_opt) => {
                self.visit_expression(array, all_findings, file, context);
                if let Some(index) = index_opt {
                    self.visit_expression(index, all_findings, file, context);
                }
            }
            Expression::ArraySlice(_, array, start_opt, end_opt) => {
                self.visit_expression(array, all_findings, file, context);
                if let Some(start) = start_opt {
                    self.visit_expression(start, all_findings, file, context);
                }
                if let Some(end) = end_opt {
                    self.visit_expression(end, all_findings, file, context);
                }
            }
            Expression::ArrayLiteral(_, elements) => {
                for element in elements {
                    self.visit_expression(element, all_findings, file, context);
                }
            }

            Expression::FunctionCall(_, function, args) => {
                self.visit_expression(function, all_findings, file, context);
                for arg in args {
                    self.visit_expression(arg, all_findings, file, context);
                }
            }
            Expression::FunctionCallBlock(_, function, block) => {
                self.visit_expression(function, all_findings, file, context);
                self.visit_statement(block, all_findings, file, context);
            }
            Expression::NamedFunctionCall(_, function, args) => {
                self.visit_expression(function, all_findings, file, context);
                for arg in args {
                    self.visit_expression(&arg.expr, all_findings, file, context);
                }
            }

            Expression::MemberAccess(_, object, _) => {
                self.visit_expression(object, all_findings, file, context);
            }

            Expression::Parenthesis(_, expr) => {
                self.visit_expression(expr, all_findings, file, context);
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
        context: &AnalysisContext,
    ) {
        for callback in &self.statement_callbacks {
            all_findings.extend(callback(statement, file, context));
        }

        match statement {
            Statement::Block {
                loc: _,
                unchecked: _,
                statements,
            } => {
                for stmt in statements {
                    self.visit_statement(stmt, all_findings, file, context);
                }
            }
            Statement::If(_, condition, true_branch, false_branch_opt) => {
                self.visit_expression(condition, all_findings, file, context);
                self.visit_statement(true_branch, all_findings, file, context);
                if let Some(false_branch) = false_branch_opt {
                    self.visit_statement(false_branch, all_findings, file, context);
                }
            }
            Statement::While(_, condition, body) => {
                self.visit_expression(condition, all_findings, file, context);
                self.visit_statement(body, all_findings, file, context);
            }
            Statement::DoWhile(_, body, condition) => {
                self.visit_statement(body, all_findings, file, context);
                self.visit_expression(condition, all_findings, file, context);
            }
            Statement::For(_, init_opt, condition_opt, update_opt, body_opt) => {
                if let Some(init) = init_opt {
                    self.visit_statement(init, all_findings, file, context);
                }
                if let Some(condition) = condition_opt {
                    self.visit_expression(condition, all_findings, file, context);
                }
                if let Some(update) = update_opt {
                    self.visit_expression(update, all_findings, file, context);
                }
                if let Some(body) = body_opt {
                    self.visit_statement(body, all_findings, file, context);
                }
            }
            Statement::Expression(_, expr) => {
                self.visit_expression(expr, all_findings, file, context);
            }
            Statement::VariableDefinition(_, variable_decl, init_expr_opt) => {
                self.visit_expression(&variable_decl.ty, all_findings, file, context);
                if let Some(init_expr) = init_expr_opt {
                    self.visit_expression(init_expr, all_findings, file, context);
                }
            }
            Statement::Return(_, expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr, all_findings, file, context);
                }
            }
            Statement::Emit(_, expr) => {
                self.visit_expression(expr, all_findings, file, context);
            }
            Statement::Revert(_, _, args) => {
                for arg in args {
                    self.visit_expression(arg, all_findings, file, context);
                }
            }
            Statement::RevertNamedArgs(_, _, args) => {
                for arg in args {
                    self.visit_expression(&arg.expr, all_findings, file, context);
                }
            }
            Statement::Try(_, expr, returns_opt, catch_clauses) => {
                self.visit_expression(expr, all_findings, file, context);

                if let Some((_, returns_block)) = returns_opt {
                    self.visit_statement(returns_block, all_findings, file, context);
                }

                for catch_clause in catch_clauses {
                    match catch_clause {
                        solang_parser::pt::CatchClause::Simple(_, _, stmt) => {
                            self.visit_statement(stmt, all_findings, file, context);
                        }
                        solang_parser::pt::CatchClause::Named(_, _, _, stmt) => {
                            self.visit_statement(stmt, all_findings, file, context);
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
                    self.visit_expression(&arg.expr, all_findings, file, context);
                }
            }
        }
    }

    pub fn traverse(&self, file: &SolidityFile, context: &AnalysisContext) -> Vec<FindingData> {
        let mut all_findings: Vec<FindingData> = Vec::new();
        self.visit_source_unit(&file.source_unit, &mut all_findings, file, context);
        all_findings
    }
}
