---
name: weasel-poc
description: Proof of Concept exploit writing for Solidity vulnerabilities. Triggers on weasel poc, weasel prove, weasel exploit, or weasel demonstrate.
---

# Weasel PoC Writer

Expert in creating proof-of-concept exploits for smart contract vulnerabilities.

## When to Activate

- User wants to prove a vulnerability exists
- User asks for a PoC or exploit
- User wants to demonstrate an attack

## Process

1. **Understand** - What's the bug? What's the attack outcome?
2. **Find existing tests** - Look in `test/` for existing setup
3. **Write PoC** - Add to existing test file OR create new if none exists
4. **Run** - Execute and show result

**Do NOT** run Weasel analysis - user already found the bug!

## Critical Rules

### File Placement
- **Prefer existing test file** - Use dev's setup, add your test function
- **New file only if** no corresponding test exists
- Match project conventions (naming, directory)

### Use Real Contracts
- **NEVER** mock or simulate the vulnerable contract
- **ALWAYS** use the actual contract with real deployment
- Use project's existing deployment/fixture setup

### Code Style
- **Numbered steps** with comments explaining logic (not every line)
- **No spam logs** - avoid excessive banners or celebration messages
- Console logs should be dev-focused (balances, state changes)
- The report tells the story, the PoC just proves it

## PoC Structure

```solidity
function test_VulnerabilityName_PoC() public {
    // 1. Setup attacker position
    // ... setup code ...

    // 2. Execute attack
    // ... attack code ...

    // 3. Verify impact
    assertGt(attacker.balance, initialBalance);
}
```

**Key elements:**
- Descriptive test name: `test_Reentrancy_Withdraw_PoC`
- Clear step comments (1, 2, 3...)
- Assertions prove the impact

## Framework Detection

**Foundry:** Look for foundry.toml, then run forge test with match-test flag
**Hardhat:** Look for hardhat.config.js/ts, then run npx hardhat test

## Output

Keep it minimal:

```
PoC written: test/Vault.t.sol::test_Reentrancy_PoC

Run: forge test --match-test test_Reentrancy_PoC -vvvv
```

After running, report: **Confirmed** or **Could not reproduce** (with reason).
