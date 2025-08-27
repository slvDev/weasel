use crate::core::context::AnalysisContext;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::SolidityFile;
use solang_parser::parse;
use std::path::PathBuf;
use std::sync::Arc;

pub fn run_detector_on_code(
    detector: Arc<dyn Detector>,
    code: &str,
    filename: &str,
) -> Vec<Location> {
    // Parse the code
    let parse_result = parse(code, 0);
    assert!(
        parse_result.is_ok(),
        "Parsing failed: {:?}",
        parse_result.err()
    );
    let (source_unit, _comments) = parse_result.unwrap();

    // Create a SolidityFile
    let mut file = SolidityFile::new(PathBuf::from(filename), code.to_string(), source_unit);

    // Extract metadata (contracts, imports, etc.)
    file.extract_metadata();

    // Create analysis context and add the file
    let mut context = AnalysisContext::new();
    context.files.push(file.clone());

    // Build the cache (including inheritance resolution)
    let _ = context.build_cache();

    // Create visitor and register detector callbacks
    let mut visitor = ASTVisitor::new();
    detector.clone().register_callbacks(&mut visitor);

    // Traverse the file with context
    let findings = visitor.traverse(&file, &context);

    // Extract locations from findings
    findings.iter().map(|f| f.location.clone()).collect()
}

/// Run detector with mock inheritance setup - useful for testing inheritance-based detectors
/// without needing full base contract implementations
pub fn run_detector_with_mock_inheritance(
    detector: Arc<dyn Detector>,
    code: &str,
    filename: &str,
    mock_contracts: Vec<(&str, Vec<&str>)>, // (contract_name, inheritance_chain)
) -> Vec<Location> {
    // Parse the code
    let parse_result = parse(code, 0);
    assert!(
        parse_result.is_ok(),
        "Parsing failed: {:?}",
        parse_result.err()
    );
    let (source_unit, _comments) = parse_result.unwrap();

    // Create a SolidityFile
    let mut file = SolidityFile::new(PathBuf::from(filename), code.to_string(), source_unit);

    // Extract metadata (contracts, imports, etc.)
    file.extract_metadata();

    // Create analysis context and add the file
    let mut context = AnalysisContext::new();
    context.files.push(file.clone());

    // Build the cache
    let _ = context.build_cache();

    // Inject mock inheritance chains
    for (contract_name, inheritance) in mock_contracts {
        let qualified_name = format!("{}:{}", filename, contract_name);
        if let Some(contract) = context.contracts.get_mut(&qualified_name) {
            contract.inheritance_chain = inheritance.iter().map(|s| s.to_string()).collect();
        }
    }

    // Create visitor and register detector callbacks
    let mut visitor = ASTVisitor::new();
    detector.clone().register_callbacks(&mut visitor);

    // Traverse the file with context
    let findings = visitor.traverse(&file, &context);

    // Extract locations from findings
    findings.iter().map(|f| f.location.clone()).collect()
}
