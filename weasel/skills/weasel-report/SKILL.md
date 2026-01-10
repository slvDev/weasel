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

## Process

1. **Gather info** - What's the vuln? Which contract/function? Severity?
2. **Read code** - Get exact lines and context
3. **Format report** - Use template below
4. **PoC decision** - Auto-include if High severity or already written

**Do NOT** run Weasel analysis - user already found the bug!

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

### PoC (omit if none)
See: test/Contract.t.sol::test_VulnName_PoC
```

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
