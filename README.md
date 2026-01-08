<h1 align="center">Weasel</h1>

<p align="center">
  <strong>Solidity static analyzer you can talk to</strong>
</p>

<p align="center">
  Ask your AI assistant to audit your contracts. Get explained results.
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/install-weaselup-green.svg" alt="Install"></a>
  <img src="https://img.shields.io/badge/⚡-Blazing_Fast-orange" alt="Blazing Fast">
</p>

<p align="center">
  <img src="assets/demo.gif" alt="Weasel demo" width="800">
</p>

```bash
weasel mcp add  # one-time setup, restart your AI tool
```

Now just ask:

> "Analyze my contracts with weasel"

> "What high severity issues did weasel find?"

> "Explain the reentrancy vulnerability and how to fix it"

> "Run weasel on src/Token.sol"

Weasel runs the analysis. Your AI explains the results and helps you fix them.

---

## Features

- **Blazing Fast** — Parallel Rust analysis, instant MCP responses
- **AI Integration** — Native MCP server for Claude Code, Cursor, and Windsurf
- **Extensive Detectors** — Vulnerabilities, gas optimizations, and code quality checks
- **Auto-Detection** — Automatically configures for Foundry, Hardhat, and Truffle projects
- **Flexible Output** — Markdown or JSON reports, stdout or file

---

## Why Weasel?

|                    | Weasel                           | Other Analyzers              |
| ------------------ | -------------------------------- | ---------------------------- |
| **AI Integration** | Native MCP server                | Copy-paste output to ChatGPT |
| **Setup**          | `weasel mcp add`                 | Manual config, scripts       |
| **Workflow**       | Ask questions, get answers       | Read reports, search fixes   |
| **Context**        | AI sees code + findings together | Context lost between tools   |
| **Speed**          | Parallel Rust analysis           | Often single-threaded        |

---

## Installation

```bash
curl -L https://raw.githubusercontent.com/slvDev/weasel/main/weaselup/install | bash
```

Update anytime with `weaselup`.

<details>
<summary>From Source</summary>

```bash
git clone https://github.com/slvDev/weasel.git
cd weasel && cargo build --release
```

</details>

---

## Supported AI Tools

| Tool        | Status | Setup                              |
| ----------- | ------ | ---------------------------------- |
| Claude Code | ✅     | `weasel mcp add --target claude`   |
| Cursor      | ✅     | `weasel mcp add --target cursor`   |
| Windsurf    | ✅     | `weasel mcp add --target windsurf` |

```bash
weasel mcp add      # auto-detect all
weasel mcp remove   # remove from all
```

---

## What It Detects

| Severity   | What                     | Examples                                        |
| ---------- | ------------------------ | ----------------------------------------------- |
| **High**   | Critical vulnerabilities | Reentrancy, unchecked calls, delegatecall risks |
| **Medium** | Security concerns        | Missing access control, oracle manipulation     |
| **Low**    | Best practices           | Unlocked pragma, zero-address checks            |
| **Gas**    | Optimizations            | Storage reads, loop efficiency, packing         |
| **NC**     | Code quality             | Naming, style, documentation                    |

Run `weasel detectors` to see all checks, or ask your AI: _"what can weasel detect?"_

---

## How It Works

<p align="center">
  <img src="assets/flow.png" alt="Weasel flow" width="800">
</p>

<p align="center">
  Your AI calls Weasel via MCP, gets structured findings, and explains them to you.
</p>

| MCP Command              | What It Does                        |
| ------------------------ | ----------------------------------- |
| `weasel_analyze`         | Scan contracts, get compact summary |
| `weasel_finding_details` | Deep dive into specific issues      |
| `weasel_detectors`       | List all available checks           |

---

## Standalone Usage

No AI? Weasel works great from the terminal.

```bash
weasel run                              # analyze ./src
weasel run -s ./contracts               # specify path
weasel run -e ./test -e ./mocks         # exclude paths
weasel run -m High                      # only critical
weasel run -o report.md                 # save report
weasel run -o report.json -f json       # JSON format
```

### Detectors

```bash
weasel detectors                # list all
weasel detectors -s High        # filter by severity
weasel detectors -d <id>        # details for one
```

### Configuration

Create `weasel.toml` with `weasel init`:

```toml
scope = ["src", "contracts"]
exclude = ["test", "script"]
min_severity = "Low"
format = "md"
remappings = ["@openzeppelin/=lib/openzeppelin-contracts/"]
```

| Option           | Short | Default           |
| ---------------- | ----- | ----------------- |
| `--scope`        | `-s`  | `["src"]`         |
| `--exclude`      | `-e`  | `["lib", "test"]` |
| `--min-severity` | `-m`  | `NC`              |
| `--format`       | `-f`  | `md`              |
| `--output`       | `-o`  | stdout            |
| `--remappings`   | `-r`  | auto              |

**Priority:** CLI flags > config file > auto-detection

---

## Project Support

**Foundry** — Remappings loaded in order:

1. Default paths (`forge-std/`, `@openzeppelin/`)
2. `remappings.txt`
3. `foundry.toml`
4. CLI `-r` flags

**Hardhat / Truffle** — Auto-detects config, uses `node_modules/`, defaults to `./contracts`

---

## FAQ

<details>
<summary><strong>AI can't find Weasel?</strong></summary>

```bash
which weasel          # should show path
weasel mcp add        # re-run setup
# restart your AI tool
```

</details>

<details>
<summary><strong>How do I check MCP config?</strong></summary>

```bash
cat ~/.claude.json              # Claude Code
cat ~/.cursor/mcp.json          # Cursor
cat ~/.codeium/windsurf/mcp_config.json  # Windsurf
```

</details>

<details>
<summary><strong>Manual MCP setup</strong></summary>

Add to your AI tool's config:

```json
{
  "mcpServers": {
    "weasel": {
      "type": "stdio",
      "command": "/path/to/weasel",
      "args": ["mcp", "serve"]
    }
  }
}
```

</details>

<details>
<summary><strong>How do I exclude test files?</strong></summary>

```bash
weasel run -e ./test -e ./src/mocks
```

</details>

<details>
<summary><strong>How do I analyze only critical issues?</strong></summary>

```bash
weasel run -m High
```

</details>

---

## License

MIT — [LICENSE.md](LICENSE.md)
