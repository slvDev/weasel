---
name: weasel-filter
description: False positive filtering for Weasel static analysis results. Triggers on weasel filter, weasel triage, or weasel clean report.
---

# Weasel Filter

Expert in filtering false positives from Weasel static analysis output.

**Context:** This skill filters WEASEL's output. For validating your own attack ideas, see weasel-validate.

## When to Activate

- After running Weasel analysis
- User wants to filter false positives
- User asks to triage/clean the report
- User asks "are these findings real?"

## When NOT to Use

- No Weasel analysis has been run yet (→ weasel-analyzer first)
- User wants to validate their OWN attack idea (→ weasel-validate)
- User wants deeper manual review (→ weasel-analyzer in Review Mode)

## Filtering Strategy

### Priority Triage

```
┌─────────────────────────────────────────┐
│  HIGH SEVERITY (typically 0-5 issues)   │
│  → Verify ALL - these are critical      │
├─────────────────────────────────────────┤
│  MEDIUM SEVERITY (typically 2-10)       │
│  → Verify ALL - these matter            │
├─────────────────────────────────────────┤
│  LOW SEVERITY (can be many)             │
│  → Sample check if >10 issues           │
│  → Check all if ≤10 issues              │
├─────────────────────────────────────────┤
│  GAS / NC                               │
│  → Skip verification (not security)     │
└─────────────────────────────────────────┘
```

## Two Workflows

### Workflow A: Filter In-Memory (No Report File)

When user just ran `weasel_analyze` via MCP:

1. Get findings from weasel_analyze output
2. For each High/Medium:
   - Read source code at location
   - Verify: true positive or false positive?
3. Report confirmed findings only

### Workflow B: Clean Existing Report File (Context-Efficient)

When report file already exists (user ran weasel with output flag):

1. **Don't read the full report** - it's too large
2. Get summary via `weasel_analyze` MCP (small)
3. For each High/Medium finding:
   - Read SOURCE CODE (not the report)
   - Determine: true or false positive?
4. For false positives:
   - Use Edit tool to DELETE that section from report.md
   - Find section header (e.g., `## [H-01] Reentrancy...`)
   - Delete entire section until next `## [` or end

**Why Workflow B is efficient:**
- Full report stays on disk (never in context)
- Only load: summary (~2KB) + source code
- Edit file directly instead of regenerating

## Verification Process

For each finding to verify:

1. **Check known issues** - Is this documented in README or known-issues.md?
2. **Read the code** - Use Read tool at the reported location
3. **Understand context** - Check surrounding functions, modifiers
4. **Check for guards** - Look for existing protections
5. **Assess exploitability** - Can this actually be exploited?
6. **Verdict** - Confirmed, False Positive, or Known Issue

## Verification Checklists

### Reentrancy
- [ ] Is there an external call?
- [ ] Is state modified AFTER the call?
- [ ] Is there a reentrancy guard?
- [ ] Can the called contract be malicious?

### Access Control
- [ ] Is the function actually privileged?
- [ ] Are there modifier checks?
- [ ] Is the caller validated elsewhere?

### Unchecked Returns
- [ ] Is the return value actually important?
- [ ] Is there error handling elsewhere?
- [ ] Using SafeERC20 or similar?

### Integer Issues
- [ ] Is unchecked{} block used?
- [ ] Is the value user-controlled?
- [ ] Can overflow/underflow cause harm?

## Common False Positive Patterns

### Reentrancy
- Read-only reentrancy (view functions)
- Trusted contract calls (own contracts)
- Already protected by mutex/nonReentrant

### Unchecked Transfer
- Intentional fire-and-forget
- Using SafeERC20
- Return value checked elsewhere

### Access Control
- Internal/private functions (not callable)
- Checked in parent function
- Initializer functions (one-time)

## Output Format

Keep output minimal - one line per finding:

```
Filtered 5 findings → 2 confirmed, 3 false positives

✓ [H-01] Reentrancy in withdraw() - confirmed
✓ [M-03] Access control missing - confirmed
✗ [H-02] Reentrancy in deposit() - has nonReentrant
✗ [M-01] Unchecked return - uses SafeERC20
✗ [M-02] Integer overflow - in unchecked{} intentionally

Removed 3 sections from report.md
```

**No verbose evidence blocks** - user can ask for details on specific findings if needed.

## After Filtering

Ask user:
- "Found X confirmed issues. Want me to write reports for them?"
- "Want me to add PoCs for High severity findings?"
- "Should I explain any of these in more detail?"

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "This detector usually has false positives" | Check THIS instance. Each case is different. |
| "The code looks safe" | READ the code. Don't judge by appearance. |
| "I'll mark as FP without reading" | ALWAYS read source code before verdict. |
| "SafeERC20 is used, so all transfer issues are FP" | Verify SafeERC20 is actually used at THAT location. |
| "This is a known pattern, must be fine" | Known patterns can still have implementation bugs. |
| "I'll confirm all High severity to be safe" | False positives waste developer time. Verify properly. |
