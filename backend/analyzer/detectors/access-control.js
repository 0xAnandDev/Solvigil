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

  function containsMsgSender(node) {
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

  function analyzeCritical(funcNode) {
    let isCritical = false;
    const localVars = new Set();
    
    if (funcNode.parameters) {
      for (const p of funcNode.parameters) {
        if (p.name) localVars.add(p.name);
      }
    }
    
    if (!funcNode.body) return false;
    
    parser.visit(funcNode.body, {
      VariableDeclaration(varNode) {
        if (varNode.name) localVars.add(varNode.name);
      }
    });

    parser.visit(funcNode.body, {
      BinaryOperation(binNode) {
        if (['=', '+=', '-=', '*=', '/='].includes(binNode.operator)) {
          if (binNode.left.type === 'Identifier') {
            if (!localVars.has(binNode.left.name)) {
              isCritical = true;
            }
          } else if (binNode.left.type === 'MemberAccess') {
            if (binNode.left.expression && binNode.left.expression.type === 'Identifier') {
               if (!localVars.has(binNode.left.expression.name)) {
                   isCritical = true;
               }
            } else {
               if (!containsMsgSender(binNode.left)) {
                   isCritical = true;
               }
            }
          } else if (binNode.left.type === 'IndexAccess') {
            if (!containsMsgSender(binNode.left.index)) {
               let baseName = '';
               if (binNode.left.base && binNode.left.base.type === 'Identifier') {
                   baseName = binNode.left.base.name;
               }
               if (baseName && !localVars.has(baseName)) {
                   isCritical = true;
               } else if (!baseName) {
                   isCritical = true;
               }
            }
          }
        }
      },
      FunctionCall(callNode) {
        if (callNode.expression && callNode.expression.type === 'MemberAccess') {
          const memberName = callNode.expression.memberName;
          if (['transfer', 'send', 'call'].includes(memberName)) {
             if (!containsMsgSender(callNode.expression.expression)) {
                isCritical = true;
             } else {
                for (const arg of callNode.arguments) {
                   let usesContractBalance = false;
                   parser.visit(arg, {
                     MemberAccess(maNode) {
                       if (maNode.memberName === 'balance') usesContractBalance = true;
                     }
                   });
                   if (usesContractBalance) {
                      isCritical = true;
                   }
                }
             }
          }
        }
        if (callNode.expression && callNode.expression.type === 'Identifier' && callNode.expression.name === 'selfdestruct') {
           isCritical = true;
        }
      }
    });
    return isCritical;
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
        const isCritical = analyzeCritical(funcNode);
        
        if (isCritical) {
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
            severity: 'HIGH',
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
            impact: 'HIGH: Any address can call critical functions. Complete loss of contract control.'
          });
        }
      }
    }
  });

  return vulnerabilities;
}

module.exports = {
  detect
};

