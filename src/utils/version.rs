// src/utils/version.rs
use semver::{Version, VersionReq};

/// "^0.8.0" -> "^0.8.0"
/// ">= 0.8.0 <= 0.9.0" -> ">=0.8.0,<=0.9.0"
fn clean_solidity_version_req(req_str: &str) -> String {
    req_str.trim().replace(" ", ",")
}

/// E.g., ">=0.8.0, <0.9.0" -> Some(0.8.0)
/// E.g., "^0.8.0" -> Some(0.8.0)
/// Returns None if parsing fails or no digits are found.
fn extract_and_parse_min_version(req_str: &str) -> Option<Version> {
    let min_ver_str = req_str
        .split(',')
        .next()
        .unwrap_or("")
        .trim_start_matches(|c: char| !c.is_digit(10));

    if min_ver_str.is_empty() {
        eprintln!(
            "Warning: Could not extract minimum version digits from '{}'",
            req_str
        );
        return None;
    }

    match Version::parse(min_ver_str) {
        Ok(ver) => Some(ver),
        Err(e) => {
            eprintln!(
                "Warning: Could not parse minimum version '{}' from '{}': {}",
                min_ver_str, req_str, e
            );
            None
        }
    }
}

pub fn solidity_version_req_matches(
    solidity_version_req_str: &str,
    required_req_str: &str,
) -> bool {
    let cleaned_solidity_req_str = clean_solidity_version_req(solidity_version_req_str);

    let solidity_req = match VersionReq::parse(&cleaned_solidity_req_str) {
        Ok(req) => req,
        Err(e) => {
            eprintln!(
                "Error parsing Solidity version requirement '{}': {}",
                cleaned_solidity_req_str, e
            );
            return false;
        }
    };

    let check_req = match VersionReq::parse(required_req_str) {
        Ok(req) => req,
        Err(e) => {
            eprintln!(
                "Error parsing required version requirement '{}': {}",
                required_req_str, e
            );
            return false;
        }
    };

    let min_check_ver_opt = extract_and_parse_min_version(required_req_str);
    let min_solidity_ver_opt = extract_and_parse_min_version(&cleaned_solidity_req_str);

    let condition_a = min_check_ver_opt
        .map(|min_check_ver| solidity_req.matches(&min_check_ver))
        .unwrap_or(false);

    let condition_b = min_solidity_ver_opt
        .map(|min_solidity_ver| check_req.matches(&min_solidity_ver))
        .unwrap_or(false);

    // Determine the final result based on whether the source requirement is a caret requirement
    let is_caret = solidity_version_req_str.trim().starts_with('^');
    if is_caret {
        condition_b
    } else {
        condition_a || condition_b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_req_matches() {
        // Exact match
        assert!(solidity_version_req_matches("0.8.4", ">=0.8.4"));

        // Caret range
        assert!(solidity_version_req_matches("^0.8.0", ">=0.8.0"));
        assert!(solidity_version_req_matches("^0.8.4", ">=0.8.4"));
        assert!(solidity_version_req_matches("^0.8.10", ">=0.8.4"));
        assert!(!solidity_version_req_matches("^0.7.0", ">=0.8.0"));
        assert!(!solidity_version_req_matches("^0.8.0", ">=0.9.0"));
        assert!(!solidity_version_req_matches("^0.8.0", ">=0.8.1"));
        assert!(solidity_version_req_matches("^0.8.1", ">=0.8.1"));
        assert!(solidity_version_req_matches("^0.8.0", ">=0.8.0, <0.9.0"));
        assert!(!solidity_version_req_matches("^0.8.0", ">=0.7.0, <0.8.0"));
        assert!(solidity_version_req_matches("^0.8.5", ">=0.8.1, <0.8.10"));

        // Greater than or equal range
        assert!(solidity_version_req_matches(">=0.8.4", ">=0.8.4"));
        assert!(solidity_version_req_matches(">=0.8.10", ">=0.8.4"));
        assert!(solidity_version_req_matches(">=0.8.0", ">=0.8.0"));
        assert!(solidity_version_req_matches(">=0.8.0", ">=0.8.4"));

        // Complex range
        assert!(solidity_version_req_matches(">=0.8.4 <0.9.0", ">=0.8.4"));
        assert!(solidity_version_req_matches(">=0.8.0 <0.8.4", ">=0.8.0"));
        assert!(!solidity_version_req_matches(">=0.8.0 <0.8.4", ">=0.8.4"));
        assert!(solidity_version_req_matches(">=0.8.0 <0.9.0", ">=0.8.5"));
        assert!(!solidity_version_req_matches(">=0.8.5 <0.9.0", ">=0.9.0"));
        assert!(solidity_version_req_matches(">=0.8.5 <0.9.0", ">=0.8.0"));
        assert!(solidity_version_req_matches(">=0.8.1", ">=0.8.0"));
        assert!(!solidity_version_req_matches(">=0.8.0 <0.8.5", ">=0.8.5"));
        assert!(solidity_version_req_matches(">=0.8.0 <=0.8.5", ">=0.8.5"));

        // Invalid inputs
        assert!(!solidity_version_req_matches("invalid", ">=0.8.0"));
        assert!(!solidity_version_req_matches("^0.8.0", "invalid"));

        // Check requires lower version than source min
        assert!(solidity_version_req_matches(">=0.8.10", ">=0.8.4"));
        assert!(solidity_version_req_matches("^0.8.10", ">=0.8.4"));

        // Check requires higher version than source allows (caret)
        assert!(!solidity_version_req_matches("^0.8.0", ">=0.9.0"));
        assert!(!solidity_version_req_matches("^0.8.5", ">=0.9.0"));

        // Check requires higher version than source allows (range)
        assert!(!solidity_version_req_matches(">=0.8.0 <0.9.0", ">=0.9.0"));

        // Whitespace variations
        assert!(solidity_version_req_matches(" >=0.8.0 ", ">=0.8.0"));
        assert!(solidity_version_req_matches(" ^0.8.0 ", ">=0.8.0"));
    }
}
