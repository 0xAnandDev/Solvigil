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

  // Removed isUserSpecific

  // 2. Find external calls followed by state updates in each function
  parser.visit(ast, {
    FunctionDefinition(funcNode) {
      if (!funcNode.body) return;

      // Check if function can recurse
      let canRecurse = true;
      if (funcNode.modifiers) {
        const hasNonReentrant = funcNode.modifiers.some(m => {
          if (!m.name) return false;
          const nameLower = m.name.toLowerCase();
          return nameLower === 'nonreentrant' || nameLower === 'lock' || nameLower.includes('entrancy') || nameLower.includes('guard');
        });
        if (hasNonReentrant) canRecurse = false;
      }
      if (funcNode.visibility === 'internal' || funcNode.visibility === 'private') {
        canRecurse = false;
      }

      let hasExternalCall = false;
      let externalCallNode = null;

      const paramNames = funcNode.parameters ? funcNode.parameters.map(p => p.name) : [];

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
        if (!hasExternalCall) return;

        const callLine = externalCallNode.loc ? externalCallNode.loc.start.line : 0;
        const assignLine = assignNode.loc ? assignNode.loc.start.line : 0;

        // Verify execution order: State update MUST be AFTER the external call
        if (callLine > 0 && assignLine > 0 && assignLine <= callLine) {
           return; // State update is BEFORE external call -> safe, don't flag
        }

        const targetName = getTargetName(assignNode.left);
        const isStateUpdate = !targetName || stateVariables.has(targetName);
        
        if (!isStateUpdate) {
           return; // skip if it's not a state update
        }

        // Check for guard modifiers (nonReentrant)
        if (!canRecurse) {
          return; // Protected by nonReentrant
        }

        let fundsInvolved = false;
        parser.visit(externalCallNode, {
          NameValueList(node) {
             if (node.names && node.names.includes('value')) fundsInvolved = true;
          },
          MemberAccess(maNode) {
             if (['transfer', 'send'].includes(maNode.memberName)) fundsInvolved = true;
          }
        });

        let severity = fundsInvolved ? 'HIGH' : 'MEDIUM';

        // Deterministic Confidence Scoring
        let confidence = (callLine > 0 && assignLine > 0 && assignLine > callLine) ? 'HIGH' : 'MEDIUM';

        const callCol = externalCallNode.loc ? externalCallNode.loc.start.column : 0;

        console.log(`[REENTRANCY] Found vulnerability at line ${callLine} with ${confidence} confidence, severity ${severity}`);
        vulnerabilities.push({
          type: 'Reentrancy',
          severity: severity,
          confidence: confidence,
          line: callLine,
          column: callCol,
          description: 'External call made before state variables are updated. An attacker could exploit this via callback.',
          code: callLine > 0 ? (lines[callLine - 1] || '').trim() : '',
          fix: 'Update state variables before making external calls. Use Checks-Effects-Interactions pattern.',
          fixExplanation: `// ❌ Vulnerable Pattern\n(bool success, ) = msg.sender.call{value: amount}("");\nrequire(success);\nbalances[msg.sender] = 0;\n\n// ✅ Fixed Pattern (Checks-Effects-Interactions)\nbalances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: amount}("");\nrequire(success);`,
          simulation: [
            `1️⃣ Attacker calls vulnerable \`${funcNode.name || 'fallback/receive'}\` function`,
            `2️⃣ Contract makes external call to attacker contract`,
            `3️⃣ Attacker contract calls back into \`${funcNode.name || 'fallback/receive'}\` (reenters)`,
            `4️⃣ \`${targetName || 'state variable'}\` not updated yet, function runs again`,
            `5️⃣ Funds transferred multiple times before \`${targetName || 'state variable'}\` is finally updated`
          ],
          impact: severity === 'HIGH' ? 'HIGH: Attacker can drain funds by exploiting callback.' : 'MEDIUM: Reentrancy possible but no funds directly at risk. May cause incorrect state behavior.'
        });

        // Reset the flag since we found one issue for this external call
        hasExternalCall = false;
      }
    }
  });

  return vulnerabilities;
}

module.exports = {
  detect
};
