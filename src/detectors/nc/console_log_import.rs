use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Import, ImportPath, SourceUnitPart};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct ConsoleLogImportDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for ConsoleLogImportDetector {
    fn id(&self) -> &str {
        "console-log-import"
    }

    fn name(&self) -> &str {
        "Delete rogue `console.log` imports"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Imports for `console.sol` or `console2.sol` (Hardhat/Foundry debugging tools) should not be present in production contracts."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        None
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_source_unit_part(move |part, file| {
            if let SourceUnitPart::ImportDirective(import) = part {
                let (path_literal, loc) = match import {
                    Import::Plain(literal, loc) => (Some(literal), loc),
                    Import::GlobalSymbol(literal, _, loc) => (Some(literal), loc),
                    Import::Rename(literal, _, loc) => (Some(literal), loc),
                };

                if let Some(ImportPath::Filename(filepath)) = path_literal {
                    let lower_path = filepath.string.to_lowercase();
                    if lower_path.contains("console.sol") || lower_path.contains("console2.sol") {
                        detector_arc.add_location(loc_to_location(loc, file));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_console_log_import_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;

            import "hardhat/console.sol"; // Positive
            import { console2 as console } from "forge-std/console2.sol"; // Positive
            import "./utils/SafeMath.sol"; // Negative

            contract Test {
                function test() public {
                    console.log("Testing");
                }
            }
        "#;
        let detector = Arc::new(ConsoleLogImportDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "contract.sol");
        assert_eq!(locations.len(), 2, "Should detect 2 console imports");
        assert_eq!(locations[0].line, 4); // hardhat/console.sol
        assert_eq!(locations[1].line, 5); // forge-std/console2.sol

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("import \"hardhat/console.sol\""),
            "Snippet for arr[0] is incorrect"
        );

        assert!(
            locations[1]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("import { console2 as console } from \"forge-std/console2.sol\""),
            "Snippet for arr[0] is incorrect"
        );
    }
}
