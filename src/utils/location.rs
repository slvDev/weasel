// src/utils/location.rs
// Utility functions for handling solang_parser::pt::Loc

use crate::models::finding::Location;
use crate::models::SolidityFile;
use solang_parser::pt::Loc;

// Default snippet text if extraction fails
const FALLBACK_SNIPPET: &str = "<code snippet unavailable>";

/// Helper to calculate 1-based line and 0-based column from byte offset
pub fn offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line_count = 1;
    let mut last_newline_offset = 0;
    // Iterate bytes up to the offset
    for (i, byte) in content.bytes().enumerate() {
        if i >= offset {
            break;
        }
        if byte == b'\n' {
            line_count += 1;
            last_newline_offset = i + 1; // Start of the next line
        }
    }
    // Ensure offset doesn't exceed content length for column calculation
    let safe_offset = std::cmp::min(offset, content.len());
    let column = safe_offset.saturating_sub(last_newline_offset);
    (line_count, column)
}

/// Optimized helper to calculate 1-based line and 0-based column using precomputed line starts.
pub fn offset_to_line_col_cached(offset: usize, line_starts: &[usize]) -> (usize, usize) {
    let line_index = line_starts.partition_point(|&start| start <= offset);

    let current_line_index = if line_index > 0 && line_starts[line_index - 1] == offset {
        line_index - 1 // Offset is exactly start of this line, belongs to previous line conceptually for line number
    } else if line_index == 0 {
        0 // Offset is on the first line
    } else {
        line_index - 1 // Belongs to the line that starts at line_starts[line_index - 1]
    };

    let line_number = current_line_index + 1;
    let line_start_offset = line_starts[current_line_index];
    let column = offset.saturating_sub(line_start_offset);

    (line_number, column)
}

/// Helper to create a Location object from solang Loc and file context
pub fn loc_to_location(loc: &Loc, file: &SolidityFile) -> Location {
    let (start_offset, end_offset) = match loc {
        Loc::File(_, start, end) => (*start, *end),
        // Handle non-file locations
        _ => {
            return Location {
                file: "<unknown>".to_string(),
                line: 1,
                column: Some(0),
                line_end: Some(1),
                column_end: Some(0),
                snippet: Some(FALLBACK_SNIPPET.to_string()),
            };
        }
    };

    let (start_line, start_col) = offset_to_line_col(&file.content, start_offset);
    // Add 1 to end_offset for exclusive range in snippet and correct end col calculation
    let exclusive_end_offset = std::cmp::min(end_offset + 1, file.content.len());
    let (end_line, end_col) = offset_to_line_col(&file.content, exclusive_end_offset);

    // Extract the code snippet
    let snippet = file
        .content
        .get(start_offset..exclusive_end_offset)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Location {
        file: file.path.to_string_lossy().to_string(),
        line: start_line,
        column: Some(start_col),
        line_end: Some(end_line),
        column_end: Some(end_col),
        snippet: snippet.or(Some(FALLBACK_SNIPPET.to_string())),
    }
}
