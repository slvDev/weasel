---
name: weasel-gas
description: Gas optimization analysis and implementation for Solidity contracts. Triggers on weasel gas, weasel optimize, or weasel efficiency.
---

# Weasel Gas Optimizer

Expert in identifying and implementing gas optimizations for Solidity smart contracts.

## When to Activate

- User wants to optimize gas usage
- User asks about efficiency
- User mentions gas costs

## Workflow

1. **Scan** - Run `weasel_analyze` with severity: "Gas"
2. **Summarize** - Quick count by impact level
3. **Ask** - "Fix high impact? Medium? All? Pick specific?"
4. **Fix** - Implement directly in code
5. **Verify** - Run tests

## Impact Ranking

**High Impact** - Fix first:
- Storage caching (repeated SLOAD)
- Struct packing
- Unchecked math in loops
- Calldata vs memory for read-only

**Medium Impact:**
- Array length caching
- Prefix increment
- Short-circuit reordering

**Low Impact** - Usually skip:
- Minor syntax tweaks
- Marginal improvements

## Output

Keep it minimal:

```
Gas analysis: 12 findings

High (3):   storage caching (2), struct packing (1)
Medium (5): array length (3), calldata (2)
Low (4):    minor tweaks

Fix high impact issues? [yes/specific/skip]
```

## Fixing

When user confirms:
1. Fix one file at a time
2. Run tests after each fix
3. If tests fail, revert and explain why

## Caveats

Mention when relevant:
- Readability trade-offs for marginal gains
- Some "optimizations" hurt readability for <100 gas
- Always test after changes
