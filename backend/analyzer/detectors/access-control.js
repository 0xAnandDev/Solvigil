const parser = require('@solidity-parser/parser');

/**
 * Detects Access Control vulnerabilities in the given AST.
 * 
 * VULNERABILITY SIGNATURE:
 * IF function_name matches critical functions: ['withdraw', 'transfer', 'mint', 'burn', 'setOwner', 'pause']
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

  const CRITICAL_FUNCTIONS = ['withdraw', 'transfer', 'mint', 'burn', 'setowner', 'pause'];

  parser.visit(ast, {
    FunctionDefinition(funcNode) {
      if (!funcNode.name || !funcNode.body) return; // Skip unnamed functions (fallback/receive) and interfaces

      const funcName = funcNode.name.toLowerCase();

      // 1. Match critical functions
      if (CRITICAL_FUNCTIONS.includes(funcName)) {
        
        // 2. Check function visibility
        // If visibility is omitted, older solidity defaults to public. Sol-parser assigns 'default'.
        const isPublic = funcNode.visibility === 'public' || 
                         funcNode.visibility === 'external' || 
                         funcNode.visibility === 'default';

        if (isPublic) {
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
              '1️⃣ Attacker sees public withdraw function',
              '2️⃣ No owner check found',
              '3️⃣ Attacker calls withdraw()',
              '4️⃣ Attacker drains all funds',
              '5️⃣ Owner has no control'
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
