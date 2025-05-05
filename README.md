# Weasel - Smart Contract Static Analysis Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Weasel is a static analysis tool designed to help developers identify potential vulnerabilities, gas optimizations, and style issues in Solidity smart contracts. It focuses on providing actionable feedback to improve code quality and security.

**Note:** Weasel is currently under active development. Features and detectors are subject to change.

## Features

- **AST-Based Analysis:** Leverages the Abstract Syntax Tree for accurate code understanding.
- **Extensible Detector Framework:** Easily add new checks for specific vulnerabilities or patterns.
- **Configurable:** Control analysis scope, minimum severity, and output format via `weasel.toml`.
- **Multiple Output Formats:** Generate reports in **JSON** or **Markdown** (default).
- **Performance Oriented:** Built with Rust for efficient analysis.

## Installation

**Prerequisite:** You need to have Rust installed. If you don't, get it from [rustup.rs](https://rustup.rs/).

### Option 1: Install via Cargo (Recommended)

```bash
cargo install weasel
```

### Option 2: Build from Source (for Developers or Pre-release)

If you want to build from the latest source code or contribute to development:

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/slvDev/weasel.git
    cd weasel
    ```
2.  **Build:**
    ```bash
    cargo build --release
    ```
    The executable will be located at `target/release/weasel`.

## Usage

### Initialize Configuration (Optional)

Create a default `weasel.toml` configuration file in the current directory:

```bash
./target/release/weasel init
```

### Analyze Contracts

Analyze specified Solidity files or directories. Settings are determined with the following priority:

1.  **Command-line flags** (e.g., `--format json`, `--min-severity Low`).
2.  Settings in `weasel.toml` (if found in the current directory or specified with `--config`).
3.  Default settings (Scope: `["src"]`, Min Severity: `NC`, Format: `md`).

```bash
# Analyze specified files/dirs
./target/release/weasel analyze ./path/to/contracts/ ./path/to/another/file.sol

# Analyze specific scope using flags and save to a JSON report
./target/release/weasel analyze --scope ./src/ --scope ./test/ --output report --format json

# Use a specific config file and override the minimum severity
./target/release/weasel analyze -c ./config/custom.toml -m Low ./path/to/project/
```

**Options:**

- `<PATHS...>`: (Positional) One or more paths to Solidity files or directories to analyze. Overridden by `--scope` if used.
- `-s, --scope <PATHS...>`: Specify paths to include in the analysis. Can be used multiple times.
- `-m, --min-severity <SEVERITY>`: Minimum severity level of detectors to _run_ (`High`, `Medium`, `Low`, `Gas`, `NC`). Overrides config file setting.
- `-f, --format <FORMAT>`: Set the report output format (`json` or `md`). Overrides config file setting. Defaults to `md`.
- `-o, --output <FILE>`: Specify a file path to write the report to. The appropriate extension (`.json` or `.md`) will be automatically added/replaced based on the chosen format. Defaults to standard output.
- `-c, --config <FILE>`: Path to a specific `weasel.toml` configuration file.

### List Detectors

List all available detectors:

```bash
./target/release/weasel detectors
```

**Options:**

- `-s, --severity <SEVERITY>`: Filter detectors by severity (`High`, `Medium`, `Low`, `Gas`, `NC`).
- `-d, --details <DETECTOR_ID>`: Show detailed information for a specific detector ID.

## Configuration (`weasel.toml`)

Weasel can be configured using a `weasel.toml` file. By default, it looks for this file in the directory where you run the command, but a different path can be specified using the `-c, --config` flag. CLI flags always take precedence over settings in this file.

Use the `weasel init` command to generate a file with default values and comments.

**Example `weasel.toml`:**

```toml
# weasel.toml

# Paths to include in the analysis.
# If omitted, defaults to ["src"]
# scope = ["src", "contracts"]

# Minimum severity level of detectors to *run* during analysis.
# Options: "High", "Medium", "Low", "Gas", "NC" (case-insensitive)
# If omitted, defaults to "NC" (run all detectors).
# min_severity = "Low"

# Output format for the report.
# Options: "json", "md" (or "markdown")
# If omitted, defaults to "md".
# output_format = "json"
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
