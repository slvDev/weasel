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

## Two Modes

### Developer Mode (Default)
User wants to **modify** their codebase for maintainability.
- Edit actual source files
- Run tests after changes
- Commit simplified code

### Auditor Mode
User wants to **understand** complex code during audit.
- Create scratch/mental simplification for analysis
- **NEVER modify files being audited**
- Output simplified version to terminal or scratch file
- Original code stays untouched

**Detection:** If in audit context (weasel-analyzer was used, or user mentions "audit"), default to Auditor Mode.

## When NOT to Use

- **Unfamiliar codebase** - Understand first (→ weasel-overview)
- **Security-critical changes** - If unsure about a pattern's purpose, don't touch it
- **No tests available** (Developer Mode only) - Can't verify behavior without tests

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

### Developer Mode
1. **Understand first** - Read the code, understand WHY it's written this way
2. **Scope** - What to simplify? (specific function, file, or recent changes)
3. **Check tests exist** - If no tests, warn user before proceeding
4. **Analyze** - Find complexity without touching security patterns
5. **Simplify** - Apply transformations via Edit tool
6. **Test** - Run tests to verify behavior preserved
7. **Report** - Summarize changes made

### Auditor Mode
1. **Understand first** - Read the code and surrounding context
2. **Scope** - What to simplify for analysis?
3. **Analyze** - Identify complexity that obscures logic
4. **Output simplified version** - Show in terminal or create scratch file
5. **DO NOT edit original files**
6. **Note** - "This is a simplified view for analysis. Original code unchanged."

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

### Developer Mode Output
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

### Auditor Mode Output
```
## Simplified View: withdraw()

*For analysis only - original code unchanged*

Core logic (ignoring guards):
1. Get user balance
2. Send ETH to user
3. Update balance

Key observations:
- CEI violation: balance updated AFTER transfer (line 45)
- External call to msg.sender (potential reentrancy target)
- No reentrancy guard visible

This reveals: Potential reentrancy in withdraw()
```

## After Simplification

- **Always run tests** to verify functionality preserved
- Offer to simplify related contracts
- Offer gas comparison if changes were significant

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "This guard looks redundant, I'll remove it" | Guards exist for reasons. Understand before removing. |
| "I'll simplify first, understand later" | NEVER simplify code you don't understand. |
| "The tests pass, so my changes are safe" | Tests can have gaps. Review changes carefully. |
| "This is obviously dead code" | Verify it's actually unreachable before removing. |
| "Fewer lines = better code" | Clarity > brevity. Don't compress for line count. |
| "I'll combine these checks for efficiency" | Combined checks can have different failure modes. Be careful. |
| "This explicit cast is unnecessary" | Explicit casts document intent. Keep them. |
