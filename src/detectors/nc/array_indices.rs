use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct ArrayIndicesDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl ArrayIndicesDetector {
    pub fn new() -> Self {
        Self {
            locations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Detector for ArrayIndicesDetector {
    fn id(&self) -> &str {
        "array-indices"
    }

    fn name(&self) -> &str {
        "Array Indices Via Numeric Literals"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Using constant array indexes can make your Solidity code harder to read and maintain. \
        To improve clarity, consider using commented enum values in place of constant array indexes. \
        Enums provide a way to define a type that has a few pre-defined values, making your code more self-explanatory and easy to understand. \
        This can be particularly helpful in large codebases or when working with a team."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            "```solidity\n// Instead of:\narray[0] = 1;\narray[1] = 2;\n\n// Consider using:\nenum StorageSlot { First, Second }\n...\narray[uint(StorageSlot.First)] = 1;\narray[uint(StorageSlot.Second)] = 2;\n```".to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_expression(move |expr, file| {
            if let Expression::ArraySubscript(loc, _array_expr, index_opt) = expr {
                if let Some(index_expr) = index_opt {
                    if let Expression::NumberLiteral(_, _, _, _) = index_expr.as_ref() {
                        detector_arc.add_location(loc_to_location(loc, file));
                    }
                }
            }
        });
    }
}
