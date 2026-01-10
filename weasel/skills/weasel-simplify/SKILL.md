---
name: weasel-simplify
description: Solidity code simplification and refactoring for clarity and maintainability. Triggers on weasel simplify, weasel refactor, or weasel clean up.
---

# Weasel Simplify

Expert Solidity code simplification specialist focused on enhancing code clarity, consistency, and maintainability while preserving exact functionality.

## When to Activate

- Developer wants to clean up code
- User asks to simplify or refactor
- User wants to improve readability
- After writing new code that could be cleaner

## Core Principles

### 1. Preserve Functionality
Never change what the code does - only how it's written. All features, outputs, and behaviors must remain identical.

### 2. Security First
Never simplify in a way that introduces vulnerabilities:
- Don't remove reentrancy guards for "simplicity"
- Don't combine checks in ways that could be bypassed
- Don't remove access control for fewer lines
- Don't reorder CEI pattern

### 3. Clarity Over Brevity
Readable code > compact code:
- Avoid nested ternaries
- Use meaningful variable names
- Keep functions focused

### 4. Gas Aware
Don't "simplify" into more expensive code. Preserve:
- Storage caching patterns
- Unchecked blocks where safe
- Calldata over memory for read-only params

## Workflow

1. **Scope** - What to simplify? (specific function, file, or recent changes)
2. **Analyze** - Find complexity without touching security patterns
3. **Simplify** - Apply transformations
4. **Test** - Run tests to verify behavior preserved
5. **Report** - Summarize changes made

## Key Simplification Patterns

### Pattern 1: Flatten Nesting → Early Returns

```solidity
// Before: Deep nesting hides logic
function withdraw(uint256 amount) external {
    if (amount > 0) {
        if (balances[msg.sender] >= amount) {
            if (!paused) {
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }
        }
    }
}

// After: Guards at top, happy path clear
function withdraw(uint256 amount) external {
    if (amount == 0) revert ZeroAmount();
    if (balances[msg.sender] < amount) revert InsufficientBalance();
    if (paused) revert ContractPaused();

    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}
```

### Pattern 2: Extract Repeated Logic → Modifiers

```solidity
// Before: Same checks in multiple functions
function deposit() external payable {
    require(msg.value > 0, "Zero");
    require(!paused, "Paused");
    // ...
}
function withdraw(uint256 amt) external {
    require(amt > 0, "Zero");
    require(!paused, "Paused");
    // ...
}

// After: DRY with modifiers
modifier whenNotPaused() {
    if (paused) revert ContractPaused();
    _;
}
modifier nonZero(uint256 value) {
    if (value == 0) revert ZeroValue();
    _;
}

function deposit() external payable whenNotPaused nonZero(msg.value) { ... }
function withdraw(uint256 amt) external whenNotPaused nonZero(amt) { ... }
```

### Pattern 3: Name Complex Conditions

```solidity
// Before: Hard to read
if (amount > 0 && amount <= max && !blocked[msg.sender] && block.timestamp >= start) { ... }

// After: Self-documenting
bool isValidAmount = amount > 0 && amount <= max;
bool isAllowedUser = !blocked[msg.sender];
bool hasStarted = block.timestamp >= start;

if (isValidAmount && isAllowedUser && hasStarted) { ... }
```

### Other Opportunities
- Remove dead/commented code
- Replace require strings with custom errors (gas savings)
- Decompose long functions
- Improve variable/function names
- Remove redundant initializations (`uint256 x = 0` → `uint256 x`)

## What NOT to Simplify

**Security patterns - preserve even if "verbose":**

```solidity
// KEEP: Reentrancy guard
function withdraw() external nonReentrant { ... }

// KEEP: CEI order (Checks-Effects-Interactions)
uint256 amount = balances[msg.sender];
balances[msg.sender] = 0;           // Effect BEFORE
(bool ok,) = msg.sender.call{value: amount}("");  // Interaction
require(ok);

// KEEP: Explicit type casts
uint128 small = uint128(bigNumber);  // Don't hide conversions

// KEEP: Unchecked blocks
unchecked { ++i; }  // Don't "simplify" to i++
```

## Output

After simplifying, report concisely:

```
Simplified: Vault.sol

Changes:
- withdraw(): 3 nested ifs → early reverts
- Created modifier: whenNotPaused (applied to 4 functions)
- Replaced 8 require strings with custom errors
- Removed 12 lines dead code

Preserved: nonReentrant, CEI pattern, onlyOwner checks

Next: Run tests → forge test
```

## After Simplification

- **Always run tests** to verify functionality preserved
- Offer to simplify related contracts
- Offer gas comparison if changes were significant
