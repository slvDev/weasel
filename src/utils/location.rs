// src/utils/location.rs
// Utility functions for handling solang_parser::pt::Loc

use crate::models::finding::Location;
use crate::models::scope::SolidityFile;
use solang_parser::pt::Loc;

// Define the fallback snippet constant here
const FALLBACK_SNIPPET: &str = "<code snippet unavailable>";

/// Optimized helper to calculate 1-based line and 0-based column using precomputed line starts.
pub fn offset_to_line_col(offset: usize, line_starts: &[usize]) -> (usize, usize) {
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

/// Converts a solang_parser Loc to our internal Location struct using cached line starts.
pub fn loc_to_location(loc: &Loc, file: &SolidityFile) -> Location {
    match loc {
        Loc::File(_, start, end) => {
            let (start_line, start_col) = offset_to_line_col(*start, &file.line_starts);
            let (end_line, end_col) = offset_to_line_col(*end, &file.line_starts);
            let snippet = file.content.get(*start..=*end).unwrap_or("").to_string();

            Location {
                file: file.path.to_string_lossy().to_string(),
                line: start_line,
                column: Some(start_col),
                line_end: Some(end_line),
                column_end: Some(end_col),
                snippet: Some(snippet),
            }
        }
        // Handle non-file locations by returning a default
        _ => Location {
            file: "<unknown>".to_string(),
            line: 1,
            column: Some(0),
            line_end: Some(1),
            column_end: Some(0),
            snippet: Some(FALLBACK_SNIPPET.to_string()),
        },
    }
}
