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
pub struct Push0OpcodeDetector;

impl Detector for Push0OpcodeDetector {
    fn id(&self) -> &'static str {
        "push0-opcode"
    }

    fn name(&self) -> &str {
        "Solidity 0.8.20+ may not work on L2s due to PUSH0"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Solidity 0.8.20 switches the default EVM version to Shanghai, which includes the PUSH0 \
         opcode. This opcode may not be implemented on all L2 chains, causing deployment failures. \
         Consider using an earlier EVM version or explicitly setting evm_version in compiler settings."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses Shanghai EVM by default
pragma solidity ^0.8.20;

// Good - use earlier version
pragma solidity ^0.8.19;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_source_unit(move |source_unit, file, _context| {
            // Skip files with interfaces or abstract contracts (per original logic)
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
                        if ident.name == "solidity" && Self::could_be_0_8_20_plus(version_req) {
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

impl Push0OpcodeDetector {
    /// Checks if the version requirement could resolve to Solidity 0.8.20+
    fn could_be_0_8_20_plus(version_req: &[VersionComparator]) -> bool {
        // First check for upper bounds that prevent 0.8.20+
        if Self::has_upper_bound_below_0_8_20(version_req) {
            return false;
        }

        for comp in version_req {
            match comp {
                VersionComparator::Plain { version, .. } => {
                    if Self::is_version_0_8_20_or_higher(version) {
                        return true;
                    }
                }
                VersionComparator::Operator { op, version, .. } => {
                    match op {
                        // ^0.8.x or ~0.8.x could resolve to 0.8.20+
                        VersionOp::Caret | VersionOp::Tilde => {
                            if Self::is_0_8_version(version) {
                                return true;
                            }
                        }
                        // >=0.8.x or >0.8.x could include 0.8.20+
                        VersionOp::GreaterEq | VersionOp::Greater => {
                            if Self::is_0_8_version(version) {
                                return true;
                            }
                        }
                        // =0.8.20 or exact match
                        VersionOp::Exact => {
                            if Self::is_version_0_8_20_or_higher(version) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                VersionComparator::Range { from, to, .. } => {
                    // Range A - B: check if upper bound allows 0.8.20+
                    if Self::is_0_8_version(from) && !Self::is_version_below_0_8_20(to) {
                        return true;
                    }
                }
                VersionComparator::Or { left, right, .. } => {
                    if Self::could_be_0_8_20_plus(&[*left.clone()])
                        || Self::could_be_0_8_20_plus(&[*right.clone()])
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Checks if there's an upper bound that prevents 0.8.20+
    fn has_upper_bound_below_0_8_20(version_req: &[VersionComparator]) -> bool {
        version_req.iter().any(|comp| {
            if let VersionComparator::Operator { op, version, .. } = comp {
                match op {
                    // <0.8.20 prevents 0.8.20+
                    VersionOp::Less => {
                        if Self::is_0_8_version(version) {
                            let patch = Self::get_patch_version(version);
                            return patch <= 20;
                        }
                    }
                    // <=0.8.19 prevents 0.8.20+
                    VersionOp::LessEq => {
                        if Self::is_0_8_version(version) {
                            let patch = Self::get_patch_version(version);
                            return patch < 20;
                        }
                    }
                    _ => {}
                }
            }
            false
        })
    }

    /// Checks if version is exactly 0.8.20 or higher
    fn is_version_0_8_20_or_higher(version: &[String]) -> bool {
        Self::is_0_8_version(version) && Self::get_patch_version(version) >= 20
    }

    /// Checks if version is below 0.8.20
    fn is_version_below_0_8_20(version: &[String]) -> bool {
        Self::is_0_8_version(version) && Self::get_patch_version(version) < 20
    }

    /// Checks if version is 0.8.x (any patch)
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
    fn test_detects_push0_versions() {
        let code = r#"
            pragma solidity ^0.8.20;
            contract Test1 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "^0.8.20");

        let code = r#"
            pragma solidity >=0.8.0;
            contract Test2 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, ">=0.8.0 could resolve to 0.8.20+");

        let code = r#"
            pragma solidity 0.8.21;
            contract Test3 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "0.8.21 exact");

        let code = r#"
            pragma solidity ^0.8.0;
            contract Test4 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "^0.8.0 floating");
    }

    #[test]
    fn test_skips_safe_versions() {
        let code = r#"
            pragma solidity 0.8.19;
            contract Test1 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity ^0.7.0;
            contract Test2 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity >=0.8.0 <0.8.20;
            contract Test3 { function foo() public {} }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity ^0.8.20;
            interface ITest { function foo() external; }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code = r#"
            pragma solidity ^0.8.20;
            abstract contract AbstractTest { function foo() public virtual; }
        "#;
        let detector = Arc::new(Push0OpcodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
