use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Import, ImportPath, SourceUnitPart};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct DraftDependencyDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for DraftDependencyDetector {
    fn id(&self) -> &str {
        "draft-dependency"
    }

    fn name(&self) -> &str {
        "Import of Draft Dependency"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Importing contracts labeled as 'draft' (e.g., from OpenZeppelin drafts) can be risky as they may not be fully audited or could change significantly in future versions."
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
                    if lower_path.contains("draft") {
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
    fn test_draft_dependency_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;

            import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol"; // Positive
            import { Utils } from "../utils/draftUtils.sol"; // Positive
            import "./SafeMath.sol"; // Negative

            contract Test {}
        "#;
        let detector = Arc::new(DraftDependencyDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(locations.len(), 2, "Should detect 2 draft imports");
        assert_eq!(locations[0].line, 4); // draft-ERC20Permit.sol
        assert_eq!(locations[1].line, 5); // draftUtils.sol
        assert!(
            locations[0].snippet.as_deref().unwrap_or("").eq(
                "import \"@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol\""
            ),
            "Snippet for first assert is incorrect"
        );
    }
}
