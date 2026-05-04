const parser = require('@solidity-parser/parser');

/**
 * Detects Access Control vulnerabilities in the given AST.
 * 
 * VULNERABILITY SIGNATURE:
 * IF function modifies global state OR transfers contract-wide funds
 * AND function is_public (not internal/private)
 * AND NO require() statement checking msg.sender == owner OR no onlyOwner modifier
 * THEN Vulnerability = Access Control (HIGH severity)
 * 
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of found vulnerabilities.
 */
function detect(ast, code) {
  const vulnerabilities = [];
  const lines = code ? code.split(/\r?\n/) : [];

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

  function isMsgSender(node) {
    let found = false;
    if (!node) return found;
    parser.visit(node, {
      MemberAccess(maNode) {
        if (maNode.expression && maNode.expression.type === 'Identifier' && maNode.expression.name === 'msg' && maNode.memberName === 'sender') {
          found = true;
        }
      }
    });
    return found;
  }

  return found;
}

function getBaseIdentifier(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'IndexAccess') return getBaseIdentifier(node.base);
  if (node.type === 'MemberAccess') return getBaseIdentifier(node.expression);
  return null;
}

function analyzeCritical(funcNode) {
  let severity = null;
  const modifiedGlobalStates = new Set();
  const modifiedUserStates = new Set();
  let hasTransferToArbitrary = false;
  let usesContractBalance = false;

  if (!funcNode.body) return null;

  parser.visit(funcNode.body, {
    BinaryOperation(binNode) {
      if (['=', '+=', '-=', '*=', '/='].includes(binNode.operator)) {
        const targetName = getBaseIdentifier(binNode.left);
        if (targetName && stateVariables.has(targetName)) {
          if (!isMsgSender(binNode.left)) {
            modifiedGlobalStates.add(targetName);
          } else {
            modifiedUserStates.add(targetName);
          }
        }
      }
    },
    FunctionCall(callNode) {
      if (callNode.expression && callNode.expression.type === 'MemberAccess') {
        const memberName = callNode.expression.memberName;
        if (['transfer', 'send', 'call'].includes(memberName)) {
          if (!isMsgSender(callNode.expression.expression)) {
            hasTransferToArbitrary = true;
          }

          for (const arg of callNode.arguments) {
            parser.visit(arg, {
              MemberAccess(maNode) {
                if (maNode.memberName === 'balance') usesContractBalance = true;
              }
            });
          }
        }
      }
      if (callNode.expression && callNode.expression.type === 'Identifier' && callNode.expression.name === 'selfdestruct') {
        severity = 'CRITICAL';
      }
    }
  });

  // 1. Modifies global state that is NOT part of a standard peer-to-peer transfer
  for (const state of modifiedGlobalStates) {
    if (!modifiedUserStates.has(state)) {
      if (!severity) severity = 'HIGH';
    }
  }

  // 2. Transfers contract's total balance
  if (usesContractBalance) {
    severity = 'CRITICAL';
  }

  // 3. Anyone can use to drain contract (arbitrary transfer without user state deduction)
  if (hasTransferToArbitrary && modifiedUserStates.size === 0) {
    severity = 'CRITICAL';
  }

  return severity;
}

parser.visit(ast, {
  FunctionDefinition(funcNode) {
    if (!funcNode.name || !funcNode.body) return; // Skip unnamed functions (fallback/receive) and interfaces

    // 1. Check function visibility
    // If visibility is omitted, older solidity defaults to public. Sol-parser assigns 'default'.
    const isPublic = funcNode.visibility === 'public' ||
      funcNode.visibility === 'external' ||
      funcNode.visibility === 'default';

    if (isPublic) {
      // 2. Analyze function body to see if it does critical operations
      const severity = analyzeCritical(funcNode);

      if (severity) {
        // 3. Check for access control modifiers (like onlyOwner, auth, onlyRole)
        let hasAccessControlModifier = false;
        if (funcNode.modifiers && funcNode.modifiers.length > 0) {
          for (const mod of funcNode.modifiers) {
            const modName = mod.name ? mod.name.toLowerCase() : '';
            if (modName.includes('only') || modName.includes('auth') || modName.includes('role')) {
              hasAccessControlModifier = true;
              break;
            }
          }
        }

        if (hasAccessControlModifier) return; // Protected by a modifier

        // 4. Check function body for require() or if() containing msg.sender
        let hasMsgSenderCheck = false;
        parser.visit(funcNode.body, {
          FunctionCall(callNode) {
            if (callNode.expression && callNode.expression.name === 'require') {
              for (const arg of callNode.arguments) {
                parser.visit(arg, {
                  MemberAccess(maNode) {
                    if (maNode.expression && maNode.expression.name === 'msg' && maNode.memberName === 'sender') {
                      hasMsgSenderCheck = true;
                    }
                  }
                });
              }
            }
          },
          IfStatement(ifNode) {
            if (ifNode.condition) {
              parser.visit(ifNode.condition, {
                MemberAccess(maNode) {
                  if (maNode.expression && maNode.expression.name === 'msg' && maNode.memberName === 'sender') {
                    hasMsgSenderCheck = true;
                  }
                }
              });
            }
          }
        });

        if (hasMsgSenderCheck) return; // Protected by manual msg.sender check

        // 5. If we reach here, no access control was found
        const line = funcNode.loc ? funcNode.loc.start.line : 0;
        const col = funcNode.loc ? funcNode.loc.start.column : 0;

        vulnerabilities.push({
          type: 'Access Control Vulnerability',
          severity: severity,
          confidence: 'MEDIUM',
          line: line,
          column: col,
          description: 'Critical function lacks access control. Anyone can call it.',
          code: line > 0 ? (lines[line - 1] || '').trim() : '',
          fix: 'Add onlyOwner modifier or require(msg.sender == owner) check.',
          fixExplanation: `// ❌ Vulnerable (public function)
function withdraw(uint amount) public {
    payable(msg.sender).transfer(amount);
}

// ✅ Fixed (with require)
function withdraw(uint amount) public {
    require(msg.sender == owner, "Not owner");
    payable(msg.sender).transfer(amount);
}`,
          simulation: [
            '1️⃣ Attacker sees public critical function without access checks',
            '2️⃣ Attacker calls the function to modify state or access funds',
            '3️⃣ Contract executes the logic because it does not verify msg.sender',
            '4️⃣ Attacker successfully manipulates contract or drains funds',
            '5️⃣ True owner loses control of the contract'
          ],
          impact: severity === 'CRITICAL' 
            ? 'CRITICAL: Anyone can drain the contract or destroy it.'
            : 'HIGH: Any address can call critical functions. Unauthorized state manipulation possible.'
        });
      }
    }
  }
});

return vulnerabilities;


module.exports = {
  detect
};

