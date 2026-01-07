<h1 align="center">Weasel</h1>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">A fast, Rust-based static analysis tool for Solidity smart contracts.</p>

## Quick Start

```bash
curl -L https://raw.githubusercontent.com/slvDev/weasel/main/weaselup/install | bash
```

```bash
weasel run
```

## Features

- **100+ Detectors** — Vulnerabilities, gas optimizations, and code quality checks
- **Auto-Detection** — Automatically configures for Foundry, Hardhat, and Truffle projects
- **Import Resolution** — Handles remappings, library paths, and relative imports
- **Parallel Analysis** — Multi-threaded processing for fast results
- **Flexible Output** — Markdown or JSON reports, stdout or file

## Installation

```bash
curl -L https://raw.githubusercontent.com/slvDev/weasel/main/weaselup/install | bash
```

To update, run `weaselup`.

### From Source

```bash
git clone https://github.com/slvDev/weasel.git
cd weasel && cargo build --release
```

## Usage

```bash
# Analyze current project (defaults to ./src)
weasel run

# Specify paths
weasel run -s ./contracts -s ./src

# Exclude paths
weasel run -s ./src -e ./src/mocks -e ./src/test

# Filter by severity
weasel run -m High      # Critical only
weasel run -m Medium    # High + Medium
weasel run -m Low       # High + Medium + Low
weasel run -m Gas       # + Gas optimizations
weasel run -m NC        # All (default)

# Output options
weasel run -o report           # report.md
weasel run -o report -f json   # report.json
```

### List Detectors

```bash
weasel detectors              # All detectors
weasel detectors -s High      # By severity
weasel detectors -d <id>      # Detector details
```

## Configuration

Create `weasel.toml` with `weasel init` or manually:

```toml
scope = ["src", "contracts"]
exclude = ["test", "script"]
min_severity = "Low"
format = "md"
remappings = ["@openzeppelin/=lib/openzeppelin-contracts/contracts/"]
```

**Priority:** CLI flags > config file > defaults

| Option | Short | Default |
|--------|-------|---------|
| `--scope` | `-s` | `["src"]` |
| `--exclude` | `-e` | `["lib", "test"]` |
| `--min-severity` | `-m` | `NC` |
| `--format` | `-f` | `md` |
| `--output` | `-o` | stdout |
| `--remappings` | `-r` | auto |

## Project Support

### Foundry

Remappings loaded in order (later overrides earlier):
1. Default library paths (`forge-std/`, `@openzeppelin/`, etc.)
2. `remappings.txt`
3. `foundry.toml`
4. CLI `-r` flags

### Hardhat / Truffle

- Auto-detects `hardhat.config.js/ts` or `truffle-config.js`
- Uses `node_modules/` for dependencies
- Default scope: `./contracts`

## Detectors

Detectors are organized by severity:

| Severity | Description |
|----------|-------------|
| **High** | Critical vulnerabilities, potential fund loss |
| **Medium** | Security issues, significant concerns |
| **Low** | Minor issues, best practices |
| **Gas** | Optimization opportunities |
| **NC** | Code quality, style |

Run `weasel detectors` to see all available checks.

## FAQ

**How do I exclude test files?**
```bash
weasel run -e ./test -e ./src/mocks
```

**How do I analyze only high-severity issues?**
```bash
weasel run -m High
```

**How do I add custom remappings?**
```bash
weasel run -r "@oz/=lib/openzeppelin/"
```

**Path doesn't exist warning?**

Weasel warns and skips non-existent paths. Check your `-s` paths.

## License

MIT — see [LICENSE.md](LICENSE.md)
