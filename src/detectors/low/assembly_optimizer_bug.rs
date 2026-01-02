use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{
    ContractTy, PragmaDirective, SourceUnitPart, VersionComparator, VersionOp,
};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AssemblyOptimizerBugDetector;

impl Detector for AssemblyOptimizerBugDetector {
    fn id(&self) -> &'static str {
        "assembly-optimizer-bug"
    }

    fn name(&self) -> &str {
        "Solidity version susceptible to assembly optimizer bug"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "In Solidity versions 0.8.13 and 0.8.14, there is an optimizer bug where, if the use of \
         a variable is in a separate assembly block from the block in which it was stored, the \
         mstore operation is optimized out, leading to uninitialized memory. Consider using \
         Solidity 0.8.15 or later which fixes this bug."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - affected by optimizer bug
pragma solidity 0.8.13;
pragma solidity 0.8.14;
pragma solidity ^0.8.0;

// Good - bug fixed
pragma solidity 0.8.15;
pragma solidity ^0.8.15;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            // Skip files with interfaces or abstract contracts
            for part in &source_unit.0 {
                if let SourceUnitPart::ContractDefinition(contract) = part {
                    if matches!(
                        contract.ty,
                        ContractTy::Interface(_) | ContractTy::Abstract(_)
                    ) {
                        return Vec::new();
                    }
                }
            }

            let mut findings = Vec::new();

            for part in &source_unit.0 {
                if let SourceUnitPart::PragmaDirective(pragma) = part {
                    if let PragmaDirective::Version(loc, ident, version_req) = pragma.as_ref() {
                        if ident.name == "solidity" && Self::could_be_affected(version_req) {
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                }
            }

            findings
        });
    }
}

impl AssemblyOptimizerBugDetector {
    /// Bug affects versions 0.8.13 and 0.8.14 only
    const AFFECTED_MIN: u32 = 13;
    const AFFECTED_MAX: u32 = 14;

    /// Checks if the version requirement could resolve to 0.8.13 or 0.8.14
    fn could_be_affected(version_req: &[VersionComparator]) -> bool {
        // Check for upper bounds that prevent affected versions
        if Self::has_upper_bound_below_affected(version_req) {
            return false;
        }

        for comp in version_req {
            match comp {
                VersionComparator::Plain { version, .. } => {
                    if Self::is_affected_version(version) {
                        return true;
                    }
                }
                VersionComparator::Operator { op, version, .. } => {
                    match op {
                        // ^0.8.x or ~0.8.x where x <= 14 could resolve to affected
                        VersionOp::Caret | VersionOp::Tilde => {
                            if Self::is_0_8_version(version) {
                                let patch = Self::get_patch_version(version);
                                // Could resolve to 0.8.13 or 0.8.14 if starting <= 14
                                if patch <= Self::AFFECTED_MAX {
                                    return true;
                                }
                            }
                        }
                        // >=0.8.x where x <= 14 could include affected
                        VersionOp::GreaterEq | VersionOp::Greater => {
                            if Self::is_0_8_version(version) {
                                let patch = Self::get_patch_version(version);
                                if patch <= Self::AFFECTED_MAX {
                                    return true;
                                }
                            }
                        }
                        // =0.8.13 or =0.8.14
                        VersionOp::Exact => {
                            if Self::is_affected_version(version) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                VersionComparator::Range { from, to, .. } => {
                    // Check if range includes 0.8.13 or 0.8.14
                    if Self::is_0_8_version(from) && Self::is_0_8_version(to) {
                        let from_patch = Self::get_patch_version(from);
                        let to_patch = Self::get_patch_version(to);
                        // Range includes affected if from <= 14 and to >= 13
                        if from_patch <= Self::AFFECTED_MAX && to_patch >= Self::AFFECTED_MIN {
                            return true;
                        }
                    }
                }
                VersionComparator::Or { left, right, .. } => {
                    if Self::could_be_affected(&[*left.clone()])
                        || Self::could_be_affected(&[*right.clone()])
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Checks if there's an upper bound that prevents 0.8.13/0.8.14
    fn has_upper_bound_below_affected(version_req: &[VersionComparator]) -> bool {
        version_req.iter().any(|comp| {
            if let VersionComparator::Operator { op, version, .. } = comp {
                match op {
                    // <0.8.13 prevents affected versions
                    VersionOp::Less => {
                        if Self::is_0_8_version(version) {
                            let patch = Self::get_patch_version(version);
                            return patch <= Self::AFFECTED_MIN;
                        }
                    }
                    // <=0.8.12 prevents affected versions
                    VersionOp::LessEq => {
                        if Self::is_0_8_version(version) {
                            let patch = Self::get_patch_version(version);
                            return patch < Self::AFFECTED_MIN;
                        }
                    }
                    _ => {}
                }
            }
            false
        })
    }

    /// Checks if version is exactly 0.8.13 or 0.8.14
    fn is_affected_version(version: &[String]) -> bool {
        if !Self::is_0_8_version(version) {
            return false;
        }
        let patch = Self::get_patch_version(version);
        patch >= Self::AFFECTED_MIN && patch <= Self::AFFECTED_MAX
    }

    /// Checks if version is 0.8.x
    fn is_0_8_version(version: &[String]) -> bool {
        version.len() >= 2 && version[0] == "0" && version[1] == "8"
    }

    /// Gets the patch version number, defaults to 0
    fn get_patch_version(version: &[String]) -> u32 {
        version
            .get(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_affected_versions() {
        let code = r#"
            pragma solidity 0.8.13;
            contract Test1 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "0.8.13 exact");

        let code = r#"
            pragma solidity 0.8.14;
            contract Test2 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "0.8.14 exact");

        let code = r#"
            pragma solidity ^0.8.0;
            contract Test3 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "^0.8.0 could resolve to 0.8.13/14");

        let code = r#"
            pragma solidity >=0.8.10;
            contract Test4 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, ">=0.8.10 could include 0.8.13/14");
    }

    #[test]
    fn test_skips_safe_versions() {
        let code = r#"
            pragma solidity 0.8.12;
            contract Test1 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity 0.8.15;
            contract Test2 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity ^0.8.15;
            contract Test3 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity >=0.8.0 <0.8.13;
            contract Test4 { function foo() public {} }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity ^0.8.13;
            interface ITest { function foo() external; }
        "#;
        let detector = Arc::new(AssemblyOptimizerBugDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
