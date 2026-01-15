---
name: weasel-report
description: Audit report writing for smart contract vulnerabilities. Triggers on weasel report, weasel write up, or weasel document.
---

# Weasel Report Writer

Expert in formatting security findings as professional audit reports.

## When to Activate

- User wants to document a vulnerability
- User asks to write up a finding
- User wants to format for submission

## When NOT to Use

- User is still exploring/validating (→ weasel-validate)
- User wants to find vulnerabilities (→ weasel-analyzer)
- User wants a PoC first (→ weasel-poc)
- Vulnerability hasn't been confirmed yet

## Process

1. **Gather info** - What's the vuln? Which contract/function? Severity?
2. **Read code** - Get exact lines and context
3. **Write report to file** - Create markdown file (see File Output below)
4. **PoC decision** - Auto-include if High severity or already written

**Do NOT** run Weasel analysis - user already found the bug!

## File Output (CRITICAL)

**ALWAYS write report to a file. NEVER output report content to terminal.**

### File Naming
```
findings/
├── H-01-reentrancy-in-withdraw.md
├── H-02-access-control-bypass.md
├── M-01-unchecked-return-value.md
└── ...
```

**Pattern:** `<SEVERITY>-<NUMBER>-<short-description>.md`

### Single Finding
```bash
# Create file
findings/H-01-reentrancy-in-withdraw.md
```

### Multiple Findings
Ask user: "Create separate files per finding, or one combined report?"
- **Separate:** `findings/H-01-xxx.md`, `findings/M-01-yyy.md` (better for submission)
- **Combined:** `findings/audit-report.md` (all findings in one file)

### After Writing
Confirm to user:
```
Report written: findings/H-01-reentrancy-in-withdraw.md
```

### Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "I'll output to terminal so user can review first" | User can review the file. Terminal output gets lost. |
| "It's just one finding, doesn't need a file" | Even one finding needs a file for submission/tracking. |
| "User didn't specify a path" | Use `findings/` directory by default. |
| "I'll paste the full PoC for completeness" | Link is complete. Full code bloats report. |
| "User's custom format had ## POC section" | Custom format doesn't mean paste code. Still use link. |

## Report Template

```markdown
## [SEVERITY-XX] Title That Describes The Impact

### Summary
One sentence: what's broken and what's the impact.

### Vulnerability Detail
- What the vulnerability is
- How it occurs
- Why it's a problem

### Impact
What an attacker can achieve (fund loss, DoS, corruption).

### Code Snippet

`path/to/file.sol#L123-L130`

\`\`\`solidity
function withdraw(uint256 amount) external {
    (bool success, ) = msg.sender.call{value: amount}(""); // @audit reentrancy
    balances[msg.sender] -= amount;
}
\`\`\`

### Recommendation

\`\`\`solidity
function withdraw(uint256 amount) external nonReentrant {
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
}
\`\`\`

### PoC
See: `test/Contract.t.sol::test_VulnName_PoC`
```

## PoC Section Rules

**Default: Link only, not full code.**

```markdown
## PoC
See: `test/Vault.t.sol::test_Reentrancy_PoC`
```

**Why link-only by default:**
- Report tells the story, PoC file proves it
- Pasting 50+ lines of test code bloats report
- PoC file can be run directly, pasted code cannot

**Exception:** Include inline PoC only if:
- User explicitly asks for full code in report
- Submission platform requires inline PoC (some bug bounties)
- PoC is very short (<15 lines)

## Title Conventions

**Good:** Specific, describes impact
- "Reentrancy in `withdraw()` allows draining of user funds"
- "Missing access control on `setFee()` allows anyone to set 100% fee"

**Bad:** Vague
- "Reentrancy vulnerability"
- "Access control issue"

## Multiple Findings

Number by severity: H-01, H-02, M-01, M-02, etc.
Order: severity first, then by location.
