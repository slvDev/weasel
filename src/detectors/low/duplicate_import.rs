use crate::detectors::Detector;
use crate::models::{severity::Severity, FindingData, Location};
use crate::core::visitor::ASTVisitor;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DuplicateImportDetector;

impl Detector for DuplicateImportDetector {
    fn id(&self) -> &'static str {
        "duplicate-import"
    }

    fn name(&self) -> &str {
        "Duplicate import statements"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Multiple import statements import the same file. This is redundant and should be \
         consolidated into a single import statement to improve code clarity and reduce \
         compilation overhead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - duplicate imports
import "./Token.sol";
import {IERC20} from "./Token.sol";
import "./Token.sol";

// Good - single import with all needed symbols
import {IERC20} from "./Token.sol";
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |_source_unit, file, _context| {
            // Collect all imports grouped by file path
            let mut import_map: HashMap<String, Vec<Location>> = HashMap::new();

            for import in &file.imports {
                import_map
                    .entry(import.import_path.clone())
                    .or_insert_with(Vec::new)
                    .push(import.loc.clone());
            }

            // Find duplicates and report all instances
            let mut findings = Vec::new();
            for (_path, locs) in import_map {
                if locs.len() > 1 {
                    // Report all duplicate instances
                    for loc in locs {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc,
                        });
                    }
                }
            }
            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_duplicate_imports() {
        let code = r#"
            import "./Token.sol";
            import {IERC20} from "./Token.sol";
            import "./Utils.sol";

            contract Test {}
        "#;
        let detector = Arc::new(DuplicateImportDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 2, "import whole file");
        assert_eq!(locations[1].line, 3, "import specific symbol from same file");
    }

    #[test]
    fn test_skips_unique_imports() {
        let code = r#"
            import "./Token.sol";
            import "./Utils.sol";
            import "./Math.sol";

            contract Test {}
        "#;
        let detector = Arc::new(DuplicateImportDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
