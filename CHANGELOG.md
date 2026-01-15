# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.5] - 2026-01-15

### Changed

#### Skill Improvements

**weasel-gas** - Chain-aware gas optimization

- Auto-detect target chain from config (foundry, hardhat, truffle)
- L2 rules: prioritize calldata reduction, skip storage micro-opts
- Cheap L1 rules (Polygon, BSC): only report >1000 gas savings
- Reject non-EVM chains (Solana, Tron, etc.)

**weasel-simplify** - Dual-mode operation

- Developer Mode: edit files, run tests, commit
- Auditor Mode: create simplified view without modifying code
- Auto-detect based on context

**weasel-poc** - Clean output

- Assertions prove the bug, not console.log
- No banners, celebration messages, or decorative output
- Pre-commit checklist

**weasel-report** - File-first output

- Always write to `findings/H-01-description.md`
- Link to PoC files instead of pasting code

**weasel-analyzer, weasel-validate, weasel-filter, weasel-overview** - Context-first

- Check README and known-issues.md before analysis
- Prevents reporting known issues or design decisions as bugs
- New verdicts: KNOWN ISSUE, BY DESIGN

**weasel-explainer** - Better guidance

- "When NOT to Use" redirects to appropriate skills

### Added

#### New Detectors

- `long-calculations` - flag complex math that may overflow
- `unchecked-low-level-call` - missing success check on call/delegatecall
- `upgradable-token-interface` - detect upgradable token patterns
- `unsafe-low-level-call` - risky low-level call usage
- `large-approval` - type(uint256).max approvals
- `assembly-abi-decode` - manual ABI decoding in assembly
- `variable-inside-loop` - storage/memory allocation in loops
- `countdown-loop` - gas-inefficient loop direction
- `combine-mappings` - mappings that could be structs
- `cached-msg-sender` - unnecessary msg.sender caching
- `cached-immutable` - redundant immutable caching
- `cached-constant` - redundant constant caching
- `assembly-storage-write` - direct sstore in assembly
- `address-this-precalculation` - address(this) computed repeatedly

## [0.4.0] - 2026-01-10

### Added

- Claude Code plugin with 9 specialized skills:
  - `weasel analyze` - security review
  - `weasel validate` - attack hypothesis check
  - `weasel filter` - false positive triage
  - `weasel poc` - writes exploit tests
  - `weasel report` - formats audit findings
  - `weasel overview` - project scoping
  - `weasel gas` - gas optimization
  - `weasel explain` - code explanation
  - `weasel simplify` - code refactoring

## [0.3.1] - 2026-01-08

### Fixed

- Show correct shell profile path in install output
- Parse foundry.toml profile.default section correctly

## [0.3.0] - 2026-01-08

### Added

- MCP (Model Context Protocol) server integration
- `detector_id` field to Finding model for better tracking

### Changed

- Improved engine API and processor output

## [0.2.1] - 2026-01-07

### Fixed

- Weaselup now skips installation if same version already installed
- Cleaner CLI output with report path feedback
- Improved detector snippets and report output
- Better README formatting

## [0.2.0] - 2026-01-07

### Added

- 100+ detectors across all severity levels:
  - **High**: Unsafe ERC20 operations, unchecked transfers, Chainlink stale prices, L2 sequencer checks, fee-on-transfer, unsafe mint/approve, tx.origin usage, and more
  - **Medium**: Missing zero address validation, unsafe ABI encode packed, division before multiplication, block timestamp deadline, initializer frontrun, and more
  - **Low**: Two-step ownership transfer, deprecated functions, centralization risks, and more
  - **Gas**: Unchecked loop increment, calldata vs memory, cache state variables, custom errors, bool storage, compound assignments, and more
  - **NC (Non-Critical)**: Naming conventions, code style, layout, documentation, and more
- Parallel file analysis using Rayon
- C3 linearization for inheritance resolution
- Import resolver and project detection (Foundry, Hardhat)
- Full contract metadata parsing and lookup API
- Comprehensive AST utilities and helpers
- MIT license

### Changed

- Auto-detect default scope per project type
- Enhanced file loading with remapping support
- Findings sorted by severity in reports

## [0.1.0] - 2026-01-06

### Added

- Initial release
- Core analysis engine with AST-based detection
- Visitor pattern for efficient single-pass traversal
- Detector registry with severity-based organization
- JSON and Markdown report output
- CLI with configuration file support
- Basic detectors for common vulnerabilities

[Unreleased]: https://github.com/slvDev/weasel/compare/v0.4.5...HEAD
[0.4.5]: https://github.com/slvDev/weasel/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/slvDev/weasel/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/slvDev/weasel/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/slvDev/weasel/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/slvDev/weasel/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/slvDev/weasel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/slvDev/weasel/releases/tag/v0.1.0
