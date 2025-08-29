# Detector Improvements

This document tracks potential improvements for existing detectors to reduce false positives and increase accuracy.

## unsafe-transferfrom

**Current Implementation:**
- Detects `transferFrom` calls with 3 arguments where one argument contains "id" or "token"
- Simple heuristic-based detection

**Potential Improvements:**
1. **Type Analysis**: Track the actual type of the variable calling `transferFrom`
   - Only flag if the caller is confirmed to be an ERC721/ERC1155 contract
   - Could use import analysis to identify token contracts
   
2. **Inheritance Analysis**: Check if the contract inherits from ERC721/ERC1155
   - Similar to `unsafe_mint` detector's initial approach
   
3. **Interface Detection**: Look for IERC721/IERC1155 interface usage
   - Check variable declarations like `IERC721 public nft`
   
4. **Smarter Parameter Analysis**: 
   - Check for `uint256` type on the third parameter
   - Look for common NFT patterns (e.g., `tokenId`, `nftId`, `_tokenId`)

## unsafe-mint

**Current Implementation:**
- Detects any `_mint` call with 2+ arguments
- No contract type checking

**Potential Improvements:**
1. **Inheritance-based Detection**: Only flag in contracts that inherit from ERC721/ERC1155
   - Already implemented in earlier version, but simplified for performance
   
2. **Import Analysis**: Check if OpenZeppelin or other NFT libraries are imported

## centralization-risk

**Current Implementation:**
- Checks function modifiers against a predefined list
- Case-insensitive pattern matching

**Potential Improvements:**
1. **Modifier Definition Analysis**: Analyze what the modifier actually does
   - Check if it contains `msg.sender == owner` or similar patterns
   
2. **Dynamic Pattern Learning**: Analyze common patterns in the codebase
   - Learn project-specific access control patterns

## deprecated-transfer

**Current Implementation:**
- Detects `transfer()` calls with exactly 1 argument
- No context checking

**Potential Improvements:**
1. **Payable Address Check**: Verify the caller is actually a payable address
   - Check for `payable()` cast or payable address type
   
2. **Context Analysis**: Distinguish between ETH transfers and token transfers

## unsafe-approve

**Current Implementation:**
- Detects `approve`/`safeApprove` calls
- Simple pattern matching

**Potential Improvements:**
1. **Zero-Check Analysis**: Look for preceding `approve(address, 0)` calls
   - Would reduce false positives for correct implementations
   
2. **SafeERC20 Detection**: Check if using OpenZeppelin's SafeERC20 library

## usdt-allowance

**Current Implementation:**
- Detects any `increaseAllowance` or `decreaseAllowance` calls
- No context about whether it's actually USDT

**Potential Improvements:**
1. **Token Type Detection**: Check if the token is actually USDT
   - Look for USDT-specific addresses or variable names
   - Check imports for USDT interfaces
   
2. **Context Analysis**: Only flag when used with known USDT addresses
   - Mainnet USDT: 0xdac17f958d2ee523a2206206994597c13d831ec7

## fee-on-transfer

**Current Implementation:**
- Detects `transferFrom`/`safeTransferFrom` calls where recipient is `address(this)`
- Uses heuristic-based token detection
- Flags all transfers to self, even when proper balance checking is done

**Potential Improvements:**
1. **Balance Check Detection**: Analyze if the function checks `balanceOf` before and after transfer
   - Don't flag if proper balance accounting is detected
   - Look for pattern: `balanceBefore = balanceOf()`, `transfer()`, `balanceAfter = balanceOf()`
   
2. **Actual Fee-on-Transfer Token Detection**: 
   - Maintain a list of known fee-on-transfer tokens
   - Check against known token addresses (e.g., some deflationary tokens)
   
3. **Smarter Context Analysis**:
   - Check if the contract has a pattern of handling received amounts properly
   - Look for `actualReceived = balanceAfter - balanceBefore` patterns
   
4. **Import Analysis**: Check for SafeERC20 usage which might indicate awareness of the issue

## unbounded-fee

**Current Implementation:**  
- Detects fee-setting functions without validation
- Checks for require/assert/if statements

**Potential Improvements:**
1. **Smarter Validation Detection**: Check the actual conditions in require/if statements
   - Verify they actually bound the fee (e.g., `require(fee <= MAX_FEE)`)
   - Current implementation just checks for presence of validation, not its effectiveness

2. **Percentage Detection**: Check if fees are validated to be under 100% (or 10000 basis points)

## eip712-compliance

**Current Implementation:**
- Detects `keccak256()` calls on complex types (arrays, structs, mappings)
- Uses AST structure patterns for direct detection (array access, member access)
- Falls back to name heuristics for simple variables

**Potential Improvements:**
1. **Full Type Extraction to Context**: Extract and store variable type information during parsing
   - Would allow accurate type checking for all variables
   - Similar to how we store function names in context
   - Significant architectural change - needs careful design
   
2. **Local Type Tracking**: Track variable declarations within function scope
   - Less invasive than full context change
   - Could catch local variables with known types
   
3. **Parameter Type Analysis**: For function parameters, types are available in the AST
   - Could check parameter types when they're used with keccak256

## l2-sequencer-check

**Current Implementation:**
- Detects `latestRoundData()` calls where the answer field (position 1) is not captured
- Assumes if answer is captured, it might be for sequencer status checking
- Flags direct calls without any value capture

**Potential Improvements:**
1. **Dual Feed Detection**: Properly detect when a function uses two feeds (sequencer + price)
   - Look for multiple `latestRoundData()` calls in same function
   - First should check `answer == 0` or `answer == 1` (sequencer check pattern)
   - Second would be the actual price feed
   
2. **Sequencer Pattern Recognition**: Identify actual sequencer check patterns
   - Look for `answer == 0` (sequencer up) or `answer == 1` (sequencer down)
   - Check for grace period validation with `startedAt` timestamp
   - Identify sequencer-related variable names (sequencerFeed, uptimeFeed, etc.)
   
3. **Chain-Specific Detection**: Only flag on actual L2 chains
   - Could check for L2-specific imports or contract patterns
   - Arbitrum, Optimism, Base, etc. specific detection
   
4. **Modifier Analysis**: Check if sequencer checks are in modifiers
   - The check might be in a modifier rather than the function itself
   
5. **Cross-Function Analysis**: Track sequencer checks across functions
   - One function might check sequencer, another uses price
   - Need to understand the call flow

## direct-supports-interface

**Current Implementation:**
- Simple check for any `.supportsInterface()` member function call
- Uses `on_expression` callback for simplicity

**Potential Improvements:**
1. **Whitelist Safe Patterns**: Don't flag when using OpenZeppelin's ERC165Checker
   - Check for `using ERC165Checker for address` declarations
   - Identify safe wrapper functions
   
2. **Staticcall Detection**: Don't flag when already using staticcall
   - Check if the call is within a staticcall wrapper
   - Look for gas-limited patterns

## General Improvements

1. **Cross-Function Analysis**: Track variable types across functions
2. **Import Resolution**: Better understanding of imported contracts and interfaces
3. **Project-Specific Configuration**: Allow users to specify patterns to ignore
4. **Machine Learning**: Use ML to identify patterns from large contract datasets
5. **Semantic Analysis**: Understand the actual behavior rather than just patterns
6. **Type System Integration**: Build a comprehensive type tracking system in context
   - Store variable declarations with their types
   - Track type modifications (casts, conversions)
   - Enable accurate type-based detection across all detectors