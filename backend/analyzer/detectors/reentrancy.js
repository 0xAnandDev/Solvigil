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

  // Helper to determine if the target address might be user-controlled
  function isUserControlled(node, paramNames, stateVariables) {
    if (!node) return false;

    if (node.type === 'MemberAccess') {
      if (node.expression && node.expression.type === 'Identifier') {
        if (node.expression.name === 'msg' && node.memberName === 'sender') return true;
        if (node.expression.name === 'tx' && node.memberName === 'origin') return true;
      }
      return isUserControlled(node.expression, paramNames, stateVariables);
    }

    if (node.type === 'Identifier') {
      const name = node.name;
      if (['this', 'address', 'msg', 'tx', 'block', 'require', 'assert'].includes(name)) return false;
      if (stateVariables.has(name)) return false;
      return true;
    }

    if (node.type === 'FunctionCall') {
      if (node.arguments) {
        for (const arg of node.arguments) {
          if (isUserControlled(arg, paramNames, stateVariables)) return true;
        }
      }
      return isUserControlled(node.expression, paramNames, stateVariables);
    }

    if (node.type === 'IndexAccess') {
      return isUserControlled(node.base, paramNames, stateVariables) || isUserControlled(node.index, paramNames, stateVariables);
    }

    return false;
  }

  // Helper to extract the target expression of an external call
  function getExternalCallTarget(node) {
    let current = node.expression;
    while (current) {
      if (current.type === 'MemberAccess') {
        if (['call', 'transfer', 'send'].includes(current.memberName)) {
          return current.expression;
        }
        current = current.expression;
      } else if (current.expression) {
        current = current.expression;
      } else {
        break;
      }
    }
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

  function isUserSpecific(node, paramNames) {
    if (!node) return false;
    let isUser = false;
    parser.visit(node, {
      MemberAccess(maNode) {
        if (maNode.expression && maNode.expression.type === 'Identifier' && maNode.expression.name === 'msg' && maNode.memberName === 'sender') isUser = true;
        if (maNode.expression && maNode.expression.type === 'Identifier' && maNode.expression.name === 'tx' && maNode.memberName === 'origin') isUser = true;
      },
      Identifier(idNode) {
        if (paramNames && paramNames.includes(idNode.name)) isUser = true;
      }
    });
    return isUser;
  }

  // 2. Find external calls followed by state updates in each function
  parser.visit(ast, {
    FunctionDefinition(funcNode) {
      if (!funcNode.body) return;

      // Check if function can recurse
      let canRecurse = true;
      if (funcNode.modifiers) {
        const hasNonReentrant = funcNode.modifiers.some(m => 
          m.name && (m.name === 'nonReentrant' || m.name === 'lock')
        );
        if (hasNonReentrant) canRecurse = false;
      }
      if (funcNode.visibility === 'internal' || funcNode.visibility === 'private') {
        canRecurse = false;
      }

      let hasExternalCall = false;
      let externalCallNode = null;
      let isTargetControlled = false;

      const paramNames = funcNode.parameters ? funcNode.parameters.map(p => p.name) : [];

      // Traverse the body of the function to maintain lexical depth-first order
      parser.visit(funcNode.body, {
        FunctionCall(callNode) {
          if (isExternalCall(callNode)) {
            hasExternalCall = true;
            externalCallNode = callNode;
            
            const targetNode = getExternalCallTarget(callNode);
            isTargetControlled = isUserControlled(targetNode, paramNames, stateVariables);
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
            if (canRecurse && isTargetControlled) {
              const callLine = externalCallNode.loc ? externalCallNode.loc.start.line : 0;
              const callCol = externalCallNode.loc ? externalCallNode.loc.start.column : 0;
              
              const isGlobal = !isUserSpecific(assignNode.left, paramNames);
              const severity = isGlobal ? 'CRITICAL' : 'LOW';

              console.log(`[REENTRANCY] Found vulnerability at line ${callLine}`);
              vulnerabilities.push({
                type: 'Reentrancy',
                severity: severity,
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
                impact: severity === 'CRITICAL' ? 'CRITICAL: Attacker can withdraw more funds than they own by exploiting callback.' : 'LOW: User can trigger reentrancy, but it only affects their own user-specific state.'
              });
            }

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
