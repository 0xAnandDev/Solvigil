# Solvigil Detector Engine Specifications

This document outlines the architecture, methodology, and technical specifications of the Solvigil vulnerability detection engine. It serves as a reference for security engineers, auditors, and contributors understanding the system's static analysis capabilities.

---

## 1. Overview

**Detector Modules**  
Detector modules are isolated analysis scripts within the Solvigil engine that parse Abstract Syntax Trees (AST) to identify specific vulnerability patterns. Each module is strictly tailored to a known attack vector, evaluating syntax, control flow, and state interactions.

**Exploitability Validation**  
Identifying a potentially dangerous pattern is not enough. Exploitability validation ensures that the pattern exists in a reachable execution path (e.g., within a `public` or `external` function) and can be triggered by an attacker. 

**False-Positive Reduction**  
Static analysis is inherently prone to noise. High false-positive rates induce alert fatigue and erode developer trust. Solvigil significantly reduces noise by applying strict contextual boundaries, ensuring that appropriately protected functions (e.g., restricted by `onlyOwner` or `nonReentrant`) are securely filtered out.

---

## 2. Severity Classification System

Solvigil classifies vulnerabilities based on their potential financial impact and system disruption capabilities.

| Severity | Impact | Risk Assessment |
| :--- | :--- | :--- |
| **CRITICAL** | Direct loss of funds or irrecoverable contract state compromise. | Immediate, existential threat. Deployment must be halted until remediated. |
| **HIGH** | Significant state manipulation, denial of service, or logic bypass. | Severe threat. Highly likely to result in exploitation under specific conditions. |
| **MEDIUM** | Theoretical vulnerabilities, trust assumptions, or high gas consumption. | Moderate threat. Exploitability is difficult or requires privileged access. |
| **LOW** | Deviations from best practices, outdated pragmas, or minor inefficiencies. | Informational threat. Should be resolved to maintain code hygiene and standards. |

---

## 3. Confidence Levels

Confidence levels reflect the engine's certainty that a flagged issue is a true positive.

- **HIGH Confidence:** The AST structure matches the vulnerability signature exactly, with no protective modifiers detected.
- **MEDIUM Confidence:** The pattern is present, but complex state dependencies or custom modifiers obscure definitive exploitability. Manual review is required.
- **LOW Confidence:** Suspicious keywords or structures detected, but standard validation constraints were not fully met. Used primarily for informational warnings.

---

## 4. Detection Methodology

1. **AST Analysis:** The Solidity source code is converted into a structured Abstract Syntax Tree using a specialized parser.
2. **Pattern Matching:** Detectors traverse the AST seeking specific node combinations (e.g., `FunctionCall` adjacent to `StateVariableAssignment`).
3. **Context Validation:** The engine scopes the finding by traversing upwards to the function declaration to analyze visibility and modifiers.
4. **Exploitability Confirmation:** The module asserts that the vulnerable logic is exposed and not mitigated by surrounding logic or imported libraries (e.g., OpenZeppelin).

---

## 5. Detector Documentation

### Reentrancy
- **Description:** A state transition occurs after an external call. If the external call interacts with a malicious contract, it can recursively call the original function before the state is updated.
- **Severity:** CRITICAL
- **Detection Logic:** Scans for `call.value()` or external interface calls occurring prior to state variable assignments within the same function block.
- **Example Vulnerable Pattern:**
  ```solidity
  (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
  balances[msg.sender] = 0; // State update after external call
  ```
- **Exploit Scenario:** An attacker constructs a fallback function that recursively re-enters the withdrawal function, draining the contract's balance before their local balance is zeroed.
- **Recommended Fix:** Enforce the Checks-Effects-Interactions (CEI) pattern or implement a `nonReentrant` mutex.
- **False Positive Handling:** Suppresses alerts if the function is decorated with a recognized reentrancy guard or if the external call target is a trusted, immutable address.

### Integer Overflow/Underflow
- **Description:** Arithmetic operations exceed the maximum or minimum bounds of the data type, causing the value to wrap.
- **Severity:** HIGH
- **Detection Logic:** Identifies mathematical operations (`+`, `-`, `*`) without the use of SafeMath libraries in compiler versions `< 0.8.0`.
- **Example Vulnerable Pattern:**
  ```solidity
  pragma solidity ^0.7.0;
  balances[msg.sender] -= amount;
  ```
- **Exploit Scenario:** An attacker induces an underflow on their balance, resulting in a practically infinite token allowance.
- **Recommended Fix:** Upgrade compiler to `>= 0.8.0` (which has built-in bounds checking) or import OpenZeppelin's `SafeMath`.
- **False Positive Handling:** Suppresses findings for Solidity versions `>= 0.8.0` unless explicitly operating within an `unchecked` block.

### Unchecked External Call
- **Description:** Ignoring the boolean return value of a low-level external call.
- **Severity:** MEDIUM
- **Detection Logic:** Detects `call()`, `delegatecall()`, or `send()` where the return value is not captured or verified via `require()`.
- **Example Vulnerable Pattern:**
  ```solidity
  msg.sender.send(amount); // Return value ignored
  ```
- **Exploit Scenario:** The external call fails silently (e.g., due to out-of-gas), but the contract continues execution, incorrectly assuming the transfer was successful and updating state variables.
- **Recommended Fix:** Always check the return value: `require(success, "Call failed");`.
- **False Positive Handling:** Verifies if the call is wrapped in a conditional (`if (msg.sender.send(...))`) which implicitly handles the return value.

### tx.origin Authentication
- **Description:** Utilizing `tx.origin` for authorization purposes instead of `msg.sender`.
- **Severity:** HIGH
- **Detection Logic:** Flags any equivalence or assignment operations containing `tx.origin`.
- **Example Vulnerable Pattern:**
  ```solidity
  require(tx.origin == owner, "Not owner");
  ```
- **Exploit Scenario:** A victim is tricked into interacting with a malicious contract, which subsequently calls the vulnerable contract. `tx.origin` remains the victim, allowing the attacker to bypass authorization.
- **Recommended Fix:** Replace `tx.origin` with `msg.sender`.
- **False Positive Handling:** Only flags if `tx.origin` is used in a logical evaluation (`==`, `!=`) or `require` statement.

### Selfdestruct Usage
- **Description:** Unprotected access to the `selfdestruct` (or `suicide`) opcode.
- **Severity:** CRITICAL
- **Detection Logic:** Identifies `selfdestruct` invocations inside functions lacking adequate access controls (`onlyOwner`).
- **Example Vulnerable Pattern:**
  ```solidity
  function kill() public {
      selfdestruct(payable(msg.sender));
  }
  ```
- **Exploit Scenario:** An arbitrary user triggers the function, deleting the contract from the blockchain and stealing its ether balance.
- **Recommended Fix:** Strictly protect `selfdestruct` calls with multi-signature ownership or remove the functionality entirely.
- **False Positive Handling:** Validates if the function visibility is `internal` or if rigorous access modifiers are present.

### Timestamp Dependence
- **Description:** Using `block.timestamp` (or `now`) for critical logic or random number generation.
- **Severity:** LOW / MEDIUM
- **Detection Logic:** Flags conditional statements or math operations reliant on `block.timestamp`.
- **Example Vulnerable Pattern:**
  ```solidity
  if (block.timestamp % 15 == 0) { winLottery(); }
  ```
- **Exploit Scenario:** Miners can slightly manipulate block timestamps to favorably influence the outcome of the transaction.
- **Recommended Fix:** Avoid timestamps for entropy. Use decentralized oracles (e.g., Chainlink VRF) for randomness.
- **False Positive Handling:** Generally permits `block.timestamp` for long-term time checks (e.g., unlocking tokens after 30 days) as minor manipulation is inconsequential.

### Denial of Service (DoS)
- **Description:** Operations that can trap the contract in an unexecutable state, often due to unbounded loops or relying on external state.
- **Severity:** HIGH
- **Detection Logic:** Identifies `for` or `while` loops iterating over dynamically sized, user-controlled arrays, or external calls made within loops.
- **Example Vulnerable Pattern:**
  ```solidity
  for(uint i = 0; i < users.length; i++) {
      users[i].transfer(dividend);
  }
  ```
- **Exploit Scenario:** An attacker floods the `users` array. The loop eventually exceeds the block gas limit, rendering the function permanently unusable.
- **Recommended Fix:** Favor a "pull over push" payment architecture where users individually claim their funds.
- **False Positive Handling:** Ignores loops with hardcoded boundaries or arrays that are strictly managed by administrative logic.

### Unprotected Withdraw
- **Description:** Functions capable of transferring funds without authorization.
- **Severity:** CRITICAL
- **Detection Logic:** Locates `transfer`, `send`, or `call.value` operations within `public` or `external` functions lacking `require` checks or ownership modifiers.
- **Example Vulnerable Pattern:**
  ```solidity
  function withdraw(uint amount) public {
      msg.sender.transfer(amount);
  }
  ```
- **Exploit Scenario:** An attacker directly calls the function to drain the contract's entire balance.
- **Recommended Fix:** Implement `onlyOwner` modifiers or subtract amounts from user-specific balance mappings prior to transfer.
- **False Positive Handling:** Validates context for implicit authorization logic (e.g., `require(balances[msg.sender] >= amount)`).

### Delegatecall Misuse
- **Description:** Utilizing `delegatecall` to an untrusted contract, allowing it to modify the calling contract's storage.
- **Severity:** HIGH
- **Detection Logic:** Scans for `delegatecall` operations where the target address is supplied via user input or is easily modifiable.
- **Example Vulnerable Pattern:**
  ```solidity
  function execute(address _target, bytes memory _data) public {
      _target.delegatecall(_data);
  }
  ```
- **Exploit Scenario:** An attacker passes the address of a malicious contract containing a `selfdestruct` or state-overwriting function, taking full control of the proxy.
- **Recommended Fix:** Hardcode trusted logic contract addresses or strictly restrict the ability to update them.
- **False Positive Handling:** Ignores `delegatecall` when targeting internal immutable state variables.

### Uninitialized Storage Pointer
- **Description:** Declaring complex local variables (structs/arrays) without assigning them, causing them to default to storage pointer `0`.
- **Severity:** HIGH
- **Detection Logic:** Identifies variable declarations of complex types inside functions without explicit `memory` keywords or assignments.
- **Example Vulnerable Pattern:**
  ```solidity
  User u; 
  u.name = "Alice"; // Overwrites slot 0
  ```
- **Exploit Scenario:** Modifying the uninitialized variable inadvertently overwrites the contract's primary state variables (e.g., slot 0, which often holds the `owner` address).
- **Recommended Fix:** Explicitly declare data location (e.g., `User memory u`). Note: Addressed at the compiler level in Solidity `>= 0.5.0`.
- **False Positive Handling:** Restricts checks to relevant legacy compiler versions.

### Dangerous Low-Level Calls
- **Description:** Usage of inline assembly or unregulated low-level calls that bypass Solidity's type safety.
- **Severity:** MEDIUM
- **Detection Logic:** Flags `assembly { ... }` blocks and raw `call` operations.
- **Example Vulnerable Pattern:**
  ```solidity
  assembly { let x := mload(0x40) }
  ```
- **Exploit Scenario:** Mismanaging memory pointers or storage slots within assembly can lead to memory corruption or access control bypasses.
- **Recommended Fix:** Refrain from inline assembly unless absolutely critical for gas optimization, and subject such code to rigorous manual auditing.
- **False Positive Handling:** Tagged consistently as a warning for auditor visibility rather than a definitive exploit.

### Front-running Risks
- **Description:** Reliance on transaction order within a block.
- **Severity:** HIGH
- **Detection Logic:** Identifies ERC20 `approve()` race conditions or logic heavily reliant on exact market states.
- **Example Vulnerable Pattern:**
  ```solidity
  token.approve(spender, newAmount);
  ```
- **Exploit Scenario:** An attacker observes an impending transaction in the mempool and submits their own transaction with a higher gas price to execute first (e.g., extracting max value before an allowance is reduced).
- **Recommended Fix:** Use `safeIncreaseAllowance` and `safeDecreaseAllowance`, or implement commit-reveal schemes.
- **False Positive Handling:** Evaluated largely contextually; often flagged as medium confidence requiring manual verification.

### Missing Access Control
- **Description:** Sensitive administrative functions inadvertently left public.
- **Severity:** CRITICAL
- **Detection Logic:** Scans for keywords like `update`, `set`, `change`, `destroy` in `public/external` functions lacking modifiers.
- **Example Vulnerable Pattern:**
  ```solidity
  function setOwner(address newOwner) public {
      owner = newOwner;
  }
  ```
- **Exploit Scenario:** An attacker claims ownership of the contract and locks out legitimate administrators.
- **Recommended Fix:** Apply standard role-based access control (RBAC) or `onlyOwner` modifiers.
- **False Positive Handling:** Relies heavily on keyword heuristics; occasionally flags public setters designed for open ecosystems.

---

## 6. Exploitability Validation

Solvigil surpasses traditional regex scanning by incorporating an **Exploitability Validation Pipeline**:
- **Avoids Simple Regex:** Regex cannot understand scope or execution flow. Solvigil uses AST traversal to understand *where* a statement exists.
- **Validates Realistic Attack Paths:** A vulnerability is only actionable if it is reachable. The engine verifies that the function visibility is public or external, or traces internal calls back to public endpoints.
- **Reduces Noisy Results:** By verifying the presence of modifiers (like `nonReentrant` or `onlyOwner`), Solvigil prunes thousands of false positives generated by less sophisticated linters.

---

## 7. Security Score Calculation

The health of a contract is quantified via a weighted security score, starting at a baseline of `100`:
- **Severity Weighting:** 
  - CRITICAL: -35 points
  - HIGH: -20 points
  - MEDIUM: -10 points
  - LOW: -5 points
- **Multiplicity Penalty:** Repeated vulnerabilities stack penalties, rapidly decaying the score of poorly written contracts.
- **Exploitability Impact:** Findings categorized with "LOW Confidence" or identified as informational do not aggressively impact the core score, preventing artificial deflation of healthy contracts.

---

## 8. Report Generation Flow

1. **Detector Output:** Individual modules emit standard vulnerability objects.
2. **JSON Formatting:** The engine aggregates and deduplicates these objects, returning a strictly typed JSON payload to the client.
3. **Dashboard Rendering:** The frontend parses the JSON, dynamically generating interactive charts and UI cards.
4. **PDF Export Pipeline:** Solvigil renders an isolated HTML structure using the JSON data, ensuring proper pagination and print styling, before processing it through `html2pdf.js` for immediate download.

---

## 9. Future Detection Improvements

Solvigil's roadmap aims to incorporate advanced methodologies:
- **Symbolic Execution:** Integrating SMT solvers to mathematically prove the existence or absence of specific paths (e.g., proving an overflow is impossible).
- **AI-Assisted Analysis:** Leveraging Large Language Models (LLMs) to contextualize complex logic and automatically draft custom mitigation code.
- **Bytecode Scanning:** Implementing EVM decompilation to analyze verified contracts directly from the blockchain without raw source files.
- **Taint Analysis:** Tracking untrusted user input dynamically through function execution to identify data manipulation.
- **Cross-Contract Analysis:** Evaluating multi-contract interactions, proxy patterns, and systemic risks across an entire protocol ecosystem.
