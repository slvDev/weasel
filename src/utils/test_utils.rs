use crate::core::context::extract_file_metadata;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::SolidityFile;
use solang_parser::parse;
use std::path::PathBuf;
use std::sync::Arc;

fn parse_and_prepare(code: &str, filename: &str) -> SolidityFile {
    let parse_result = parse(code, 0);
    assert!(
        parse_result.is_ok(),
        "Parsing failed: {:?}",
        parse_result.err()
    );
    let (source_unit, _comments) = parse_result.unwrap();
    // println!("Source unit: {:?}", source_unit);

    let mut file = SolidityFile::new(PathBuf::from(filename), code.to_string());
    let (version, contracts) = extract_file_metadata(&source_unit);

    file.set_solidity_version(version);
    file.set_contract_definitions(contracts);
    file.set_source_unit_ast(source_unit);

    file
}

pub fn run_detector_on_code(
    detector: Arc<dyn Detector>,
    code: &str,
    filename: &str,
) -> Vec<Location> {
    let file = parse_and_prepare(code, filename);
    // println!("File: {:#?}", file);
    let files = vec![file]; // ASTVisitor expects a slice or Vec

    let mut visitor = ASTVisitor::new();
    detector.clone().register_callbacks(&mut visitor);

    visitor.traverse(&files);

    detector.locations()
}
