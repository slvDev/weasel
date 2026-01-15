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

1. **Detect Chain** - CRITICAL: Identify target chain BEFORE analysis
2. **Scan** - Run `weasel_analyze` with severity: "Gas"
3. **Filter** - Remove findings irrelevant to target chain
4. **Summarize** - Quick count by impact level (chain-adjusted)
5. **Ask** - "Fix high impact? Medium? All? Pick specific?"
6. **Fix** - Implement directly in code
7. **Verify** - Run tests

## Step 1: Chain Detection (CRITICAL - DO NOT SKIP)

**Before any gas analysis, determine the target chain.**

### Detection Methods

1. **Config files** (most reliable):
   ```
   hardhat.config.js/ts → networks: { mainnet, arbitrum, optimism, polygon, bsc }
   foundry.toml → [rpc_endpoints] or comments
   truffle-config.js → networks section
   ```

2. **README.md** - Look for deployment targets, chain mentions

3. **Dependencies/Files**:
   - `foundry.toml`, `hardhat.config.*`, `truffle-config.js` → **EVM (Supported)**
   - `@arbitrum/*` → Arbitrum L2
   - `@eth-optimism/*` → Optimism L2
   - `Anchor.toml`, `*.rs` → Solana (NOT SUPPORTED)
   - `Move.toml`, `*.move` → Move (NOT SUPPORTED)
   - `tronbox`, `tronweb` → Tron (NOT SUPPORTED)
   - No `.sol` files → NOT SUPPORTED

4. **Ask user if unclear**: "Which EVM chain is this for? (Ethereum/Arbitrum/Optimism/Polygon/BSC/Other)"
   - If user says non-EVM (Tron, Solana, etc.) → Not supported, stop.

### Chain Categories

| Category | Chains | Supported |
|----------|--------|-----------|
| **EVM L1** | Ethereum mainnet | ✓ Full |
| **EVM L2** | Arbitrum, Optimism, Base, zkSync, Scroll | ✓ Filtered |
| **EVM L1 (cheap)** | Polygon, BSC, Avalanche, Fantom | ✓ Filtered |
| **Non-EVM** | Tron, Solana, Aptos, Sui, CosmWasm, TON, etc. | ❌ NO |

**Weasel supports Solidity on EVM chains only.**

## Chain-Specific Rules

### EVM L1 (Ethereum Mainnet)
All standard gas optimizations apply:
- Storage caching (SLOAD = 2100 gas) ✓
- Struct packing ✓
- Unchecked math ✓
- Calldata vs memory ✓

### EVM L2 (Arbitrum, Optimism, Base, zkSync)
**Execution is cheap. Calldata dominates costs.**

| Optimization | Priority | Why |
|--------------|----------|-----|
| Calldata size reduction | **HIGH** | Calldata posted to L1 |
| Short strings/bytes32 | **HIGH** | Reduces calldata |
| Event data size | **HIGH** | Logged to L1 |
| Batch operations | **HIGH** | Reduces L1 overhead |
| Storage caching | Low | Execution is cheap on L2 |
| Unchecked math | Low | Saves ~20 gas, negligible |
| Struct packing | Maybe | Only if reduces calldata |

### EVM L1 Cheap (Polygon, BSC, Avalanche)
**Gas is cheap - micro-optimizations often pointless.**

| Optimization | Report? | Why |
|--------------|---------|-----|
| Storage caching | Maybe | Only for hot paths |
| Unchecked math | **Skip** | Saves cents, not worth readability |
| Prefix increment | **Skip** | Negligible savings |
| Array length caching | **Skip** | Marginal benefit |

**Rule:** Only report if saves >1000 gas or is on hot path.

### Non-EVM Chains (NOT SUPPORTED)

**Weasel analyzes Solidity on EVM only. Non-EVM chains are not supported.**

If detected (Tron, Solana, Move, CosmWasm, TON, etc.):
```
❌ Cannot run gas analysis.

This project targets a non-EVM chain.
Weasel supports Solidity on EVM chains only.

Gas optimization skill does not apply.
```

### Multi-chain / Unknown
If deploying to multiple EVM chains or unclear:
1. Ask: "Which EVM chain should I optimize for?"
2. If multi-chain, optimize for the most expensive (usually Ethereum mainnet)
3. Note that L2-specific optimizations may differ from L1

## Impact Ranking (Chain-Adjusted)

### Ethereum Mainnet

**High Impact** - Fix first:
- Storage caching (repeated SLOAD) - saves 2100+ gas
- Struct packing - saves 20000+ gas on writes
- Unchecked math in loops - saves ~60 gas per iteration
- Calldata vs memory for read-only

**Medium Impact:**
- Array length caching
- Short-circuit reordering

**Low Impact** - Usually skip:
- Prefix increment (saves 5 gas)
- Minor syntax tweaks

### L2s (Arbitrum, Optimism, Base)

**High Impact:**
- Calldata size reduction (bytes32 vs string, packed structs in calldata)
- Event data minimization
- Batch operations

**Low Impact (often skip):**
- Storage caching - execution is cheap
- Unchecked math - negligible savings
- Most "save 100 gas" tweaks

### Cheap L1s (Polygon, BSC)

**Only report if:**
- Saves >1000 gas
- Hot path (called frequently)
- Otherwise, skip - not worth readability trade-off

## Output

**Always include chain context:**

```
Gas analysis for: Arbitrum (L2)

Raw findings: 12
After chain filter: 4 relevant

High (2):   calldata size (2)
Medium (2): event optimization (2)
Filtered out (8): storage caching, unchecked math - low impact on L2

Fix high impact issues? [yes/specific/skip]
```

**For non-EVM chains:**
```
❌ Cannot run gas analysis.

Detected: Non-EVM project
Weasel supports Solidity on EVM chains only.

Gas optimization skill does not apply.
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
- **Chain matters** - L2 != L1 != non-EVM

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "Gas optimizations are universal" | **WRONG.** L2s have different cost models. Non-EVM is not supported. |
| "I'll assume Ethereum mainnet" | **WRONG.** ASK or DETECT first. Wrong chain = wrong advice. |
| "Storage caching always helps" | **WRONG on L2s.** Execution is cheap, saves negligible amounts. |
| "More optimizations = better report" | **WRONG.** Irrelevant findings waste developer time. |
| "Unchecked math is always good" | **WRONG on cheap chains.** Saves cents, hurts readability. |
| "Non-EVM is similar enough" | **WRONG.** Weasel = Solidity + EVM only. Non-EVM = not supported. |
| "I can still give general advice" | **WRONG.** If not supported, say "not supported" and stop. |

## When NOT to Use

- **Non-EVM projects** (Solana, Tron, Move, CosmWasm, TON, etc.) - Not supported. Stop and inform user.
- **No .sol files** - Nothing to analyze
- **L2-only projects** - Filter heavily, focus on calldata
- **Multi-chain** - Ask which EVM chain to optimize for
