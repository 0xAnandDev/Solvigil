const parser = require('@solidity-parser/parser');

/**
 * Detects Reentrancy vulnerabilities in the given AST.
 * 
 * VULNERABILITY SIGNATURE:
 * IF external_call (like .call(), .transfer(), .send()) FOUND
 * AND state_update (like balance = 0 or mapping assignment) FOUND AFTER the external call
 * THEN Vulnerability = Reentrancy (CRITICAL severity)
 * 
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of found vulnerabilities.
 */
function detect(ast, code) {
  console.log('[REENTRANCY] Starting detection...');
  const vulnerabilities = [];
  const lines = code ? code.split(/\r?\n/) : [];

  // 1. Collect state variables to distinguish them from local variables
  const stateVariables = new Set();
  parser.visit(ast, {
    StateVariableDeclaration(node) {
      if (node.variables) {
        node.variables.forEach(v => {
          if (v.name) stateVariables.add(v.name);
        });
      }
    }
  });

  // Helper to extract the target variable name from an assignment expression
  function getTargetName(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'IndexAccess') return getTargetName(node.base);
    if (node.type === 'MemberAccess') return getTargetName(node.expression);
    return null;
  }

  // Helper to identify if a FunctionCall is an external call (.call, .transfer, .send)
  function isExternalCall(node) {
    let current = node.expression;
    // Traverse down the expression chain to find MemberAccess with 'call', 'transfer', 'send'
    while (current) {
      if (current.type === 'MemberAccess') {
        if (['call', 'transfer', 'send'].includes(current.memberName)) {
          return true;
        }
        current = current.expression;
      } else if (current.expression) {
        current = current.expression;
      } else {
        break;
      }
    }
    return false;
  }

  // 2. Find external calls followed by state updates in each function
  parser.visit(ast, {
    FunctionDefinition(funcNode) {
      if (!funcNode.body) return;

      let hasExternalCall = false;
      let externalCallNode = null;

      // Traverse the body of the function to maintain lexical depth-first order
      parser.visit(funcNode.body, {
        FunctionCall(callNode) {
          if (isExternalCall(callNode)) {
            hasExternalCall = true;
            externalCallNode = callNode;
          }
        },
        Assignment(assignNode) {
          handleAssignment(assignNode);
        },
        BinaryOperation(assignNode) {
          if (['=', '+=', '-=', '*=', '/='].includes(assignNode.operator)) {
            handleAssignment(assignNode);
          }
        }
      });

      function handleAssignment(assignNode) {
        if (hasExternalCall) {
          const targetName = getTargetName(assignNode.left);
          
          if (!targetName || stateVariables.has(targetName)) {
            const callLine = externalCallNode.loc ? externalCallNode.loc.start.line : 0;
            const callCol = externalCallNode.loc ? externalCallNode.loc.start.column : 0;
            
            console.log(`[REENTRANCY] Found vulnerability at line ${callLine}`);
            vulnerabilities.push({
              type: 'Reentrancy',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              line: callLine,
              column: callCol,
              description: 'External call made before state variables are updated. An attacker could exploit this via callback.',
              code: callLine > 0 ? (lines[callLine - 1] || '').trim() : '',
              fix: 'Update state variables before making external calls. Use Checks-Effects-Interactions pattern.',
              fixExplanation: `// ❌ Vulnerable Pattern\n(bool success, ) = msg.sender.call{value: amount}("");\nrequire(success);\nbalances[msg.sender] = 0;\n\n// ✅ Fixed Pattern (Checks-Effects-Interactions)\nbalances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: amount}("");\nrequire(success);`,
              simulation: [
                '1️⃣ Attacker calls vulnerable function',
                '2️⃣ Contract makes external call to attacker contract',
                '3️⃣ Attacker contract calls back (reenters)',
                '4️⃣ State not updated yet, function runs again',
                '5️⃣ Funds transferred multiple times'
              ],
              impact: 'CRITICAL: Attacker can withdraw more funds than they own by exploiting callback.'
            });

            hasExternalCall = false;
          }
        }
      }
    }
  });

  return vulnerabilities;
}

module.exports = {
  detect
};
