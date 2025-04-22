use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::SolidityFile;
use solang_parser::parse;
use std::path::PathBuf;
use std::sync::Arc;

pub fn parse_and_prepare(code: &str, filename: &str) -> SolidityFile {
    let parse_result = parse(code, 0);
    assert!(
        parse_result.is_ok(),
        "Parsing failed: {:?}",
        parse_result.err()
    );
    let (source_unit, _comments) = parse_result.unwrap();

    let mut file = SolidityFile::new(PathBuf::from(filename), code.to_string());
    file.set_source_unit_ast(source_unit);
    file
}

pub fn run_detector_on_code(
    detector: Arc<dyn Detector>,
    code: &str,
    filename: &str,
) -> Vec<Location> {
    let file = parse_and_prepare(code, filename);
    let files = vec![file]; // ASTVisitor expects a slice or Vec

    let mut visitor = ASTVisitor::new();
    // Clone the Arc for registration, as register_callbacks takes ownership of the Arc
    // The original Arc `detector` is used later to retrieve locations.
    detector.clone().register_callbacks(&mut visitor);

    visitor.traverse(&files);

    // Retrieve locations from the original detector Arc
    detector.locations()
}
