# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-01-26

### Added

#### GitHub Actions

- GitHub Actions integration (`action.yml`) — run Weasel in CI/CD pipelines with `uses: slvDev/weasel@main`
- SARIF output format (`--format sarif`) for GitHub Code Scanning integration
- Nightly release workflow — automatic builds from `main` on source changes
- `weaselup --nightly` flag to install latest nightly build
- Example workflows in `gh-actions-examples/`:
  - `weasel-basic.yml` — basic analysis with SARIF upload
  - `weasel-claude.yml` / `weasel-claude-diff.yml` — Claude-powered review
  - `weasel-openai.yml` / `weasel-openai-diff.yml` — OpenAI Codex-powered review
  - `weasel-gemini.yml` / `weasel-gemini-diff.yml` — Gemini-powered review
- SHA256 checksums and build attestation for release binaries

#### Detector Configuration

- `exclude_detectors` option in `weasel.toml` and CLI (`-x` / `--exclude-detectors`) to skip specific detectors by ID
- `exclude_detectors` parameter for MCP `weasel_analyze` tool
- Protocol feature flags in `weasel.toml` `[protocol]` section to disable detector groups:
  - `uses_fot_tokens` — fee-on-transfer token detectors
  - `uses_weird_erc20` — non-standard ERC20 detectors
  - `uses_native_token` — native ETH handling detectors
  - `uses_l2` — L2-specific detectors (Arbitrum, Optimism)
  - `uses_nft` — NFT-related detectors

#### MCP & IDE Support

- OpenAI Codex CLI support for `weasel mcp add/remove` (`--target codex`)
- Gemini CLI support for `weasel mcp add/remove` (`--target gemini`)

### Changed

- Release workflow uses pinned action SHAs and Cargo caching for faster builds

## [0.4.6] - 2026-01-19

### Added

#### New Detectors

**Low**
- `constant-decimals` - prefer constants for decimals

**NC (Non-Critical)**
- `array-ranged-getter` - use ranged getter for array access
- `bool-init-false` - unnecessary boolean initialization to false
- `nc-combine-mappings` - mappings with same key can be combined into struct
- `complex-require` - complex require statements should be simplified
- `constant-expression` - expressions that could be constants
- `constructor-emit-event` - constructors should emit events
- `delete-instead-of-false` - use delete instead of setting to false
- `delete-instead-of-zero` - use delete instead of setting to zero
- `duplicate-string-literal` - duplicate string literals in code
- `empty-blocks` - empty code blocks
- `error-definition-no-args` - error definitions without arguments
- `external-call-in-modifier` - external calls in modifiers
- `floating-pragma` - floating pragma version
- `initialism-capitalization` - incorrect capitalization of initialisms (URL, ID)
- `initializer-emit-event` - initializers should emit events
- `interfaces-contracts-same-file` - interfaces and contracts in same file
- `library-in-separate-file` - libraries should be in separate files
- `many-function-params` - functions with too many parameters
- `many-return-values` - functions with too many return values
- `mixed-int-uint-style` - mixed int/uint and int256/uint256 style
- `multiple-abstract-contracts` - multiple abstract contracts in one file
- `multiple-contracts` - multiple contracts in one file
- `multiple-interfaces` - multiple interfaces in one file
- `multiple-libraries` - multiple libraries in one file
- `named-function-args` - use named function arguments for clarity
- `named-returns` - use named returns for clarity
- `prefer-custom-errors` - use custom errors instead of require/assert
- `unnamed-revert` - revert without custom error identifier
- `unused-private-function` - unused private functions
- `zero-argument` - literal zero as function argument

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

- `abstract-in-separate-file` - abstract contracts should be in separate files
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

[Unreleased]: https://github.com/slvDev/weasel/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/slvDev/weasel/compare/v0.4.6...v0.5.0
[0.4.6]: https://github.com/slvDev/weasel/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/slvDev/weasel/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/slvDev/weasel/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/slvDev/weasel/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/slvDev/weasel/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/slvDev/weasel/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/slvDev/weasel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/slvDev/weasel/releases/tag/v0.1.0
