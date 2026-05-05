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

  function validateExploitability(details) {
    // Question 1: Can this actually be exploited?
    if (!details.isPublic) return "Not exploitable";

    // Question 2: Does this require unrealistic conditions?
    if (details.severity === 'LOW') return "Not exploitable";

    // Question 3: Are there safeguards already in place?
    if (details.hasAccessControlModifier || details.hasMsgSenderCheck) return "Not exploitable";

    return "Exploitable";
  }

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

function getBaseIdentifier(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'IndexAccess') return getBaseIdentifier(node.base);
  if (node.type === 'MemberAccess') return getBaseIdentifier(node.expression);
  return null;
}

function analyzeCritical(funcNode) {
  let severity = null;
  let criticalLine = null;
  let criticalCol = null;
  let hasLoop = false;
  const modifiedGlobalStates = new Set();
  const modifiedUserStates = new Set();
  let hasTransferToArbitrary = false;
  let usesContractBalance = false;

  if (!funcNode.body) return null;

  parser.visit(funcNode.body, {
    ForStatement() { hasLoop = true; },
    WhileStatement() { hasLoop = true; },
    BinaryOperation(binNode) {
      if (['=', '+=', '-=', '*=', '/='].includes(binNode.operator)) {
        // Rule: Ensure arithmetic-only operations are NEVER flagged as access control issues
        if (['+=', '-=', '*=', '/='].includes(binNode.operator)) return;
        if (binNode.right && binNode.right.type === 'BinaryOperation' && ['+', '-', '*', '/'].includes(binNode.right.operator)) return;

        const targetName = getBaseIdentifier(binNode.left);
        if (targetName && stateVariables.has(targetName)) {
          // Check if it modifies critical/global state affecting funds or permissions
          const lowerName = targetName.toLowerCase();
          const isCriticalState = ['owner', 'admin', 'role', 'auth', 'fee', 'treasury', 'fund', 'balance', 'allowance', 'lock', 'pause', 'stop', 'config', 'state', 'status'].some(kw => lowerName.includes(kw));

          if (!isMsgSender(binNode.left)) {
            if (!isCriticalState) return; // Skip non-critical state modifications

            modifiedGlobalStates.add(targetName);
            if (!criticalLine && binNode.loc) {
              criticalLine = binNode.loc.start.line;
              criticalCol = binNode.loc.start.column;
            }
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
            if (!criticalLine && callNode.loc) {
              criticalLine = callNode.loc.start.line;
              criticalCol = callNode.loc.start.column;
            }
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
        if (!criticalLine && callNode.loc) {
          criticalLine = callNode.loc.start.line;
          criticalCol = callNode.loc.start.column;
        }
      }
    }
  });

  let isUserSpecific = modifiedUserStates.size > 0 && modifiedGlobalStates.size === 0 && !hasTransferToArbitrary;
  let isReadOnly = modifiedGlobalStates.size === 0 && modifiedUserStates.size === 0 && !hasTransferToArbitrary && !usesContractBalance && severity !== 'CRITICAL';

  if (hasLoop) {
    severity = 'LOW'; // skip batch payments/loops
  } else if (severity === 'CRITICAL') {
    // Keep CRITICAL if it's selfdestruct
  } else if (usesContractBalance || hasTransferToArbitrary || (modifiedGlobalStates.size > 0 && !isUserSpecific)) {
    severity = 'HIGH'; // actually transfers funds or changes global state
  } else {
    severity = 'LOW'; // user-specific or read-only (SKIPPED)
  }

  return { severity, line: criticalLine, column: criticalCol };
}

parser.visit(ast, {
  FunctionDefinition(funcNode) {
    if (!funcNode.name || !funcNode.body) return; // Skip unnamed functions (fallback/receive) and interfaces

    // 1. Analyze function body to see if it does critical operations
    const criticalInfo = analyzeCritical(funcNode);
    if (!criticalInfo || !criticalInfo.severity) return; // Not a critical function, ignore completely
    const severity = criticalInfo.severity;

    // --- EXPLOITABILITY CHECK ---
    let isExploitable = true;

    // Check 1: Are there guards or restrictions? (Access control modifiers)
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

    // Check 2: Are there safety checks? (require, if statements for msg.sender)
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

    // Check 3: Only flag if truly exploitable
    if (hasAccessControlModifier || hasMsgSenderCheck) {
      isExploitable = false; // Mitigated
    }

    let conditionsVerified = 1; // Condition 1: Modifies state or transfers funds

    // Condition 2: Is it public/external?
    const isPublic = funcNode.visibility === 'public' ||
      funcNode.visibility === 'external' ||
      funcNode.visibility === 'default';

    const validation = validateExploitability({
      isPublic,
      severity,
      hasAccessControlModifier,
      hasMsgSenderCheck
    });

    if (validation === "Not exploitable") {
      return; // skip the issue
    }
      
    if (isPublic) conditionsVerified++;

    if (!hasAccessControlModifier) conditionsVerified++; // Condition 3: Lacks access control modifiers
    if (!hasMsgSenderCheck) conditionsVerified++; // Condition 4: Lacks msg.sender check

    // Ensure it is actually exploitable
    if (!isExploitable) return;

    // Require ALL 4 conditions to flag
    if (conditionsVerified !== 4) return;
    
    // Deterministic Confidence Scoring
    let confidence = 'LOW';
    if (conditionsVerified === 4) confidence = 'HIGH';
    else if (conditionsVerified >= 2) confidence = 'MEDIUM';



    const line = criticalInfo.line || (funcNode.loc ? funcNode.loc.start.line : 0);
    const col = criticalInfo.column || (funcNode.loc ? funcNode.loc.start.column : 0);

    vulnerabilities.push({
      type: 'Access Control Vulnerability',
      severity: severity,
      confidence: confidence,
      line: line,
      column: col,
      description: 'Critical function may lack access control. Ensure unauthorized users cannot call it.',
      code: line > 0 ? (lines[line - 1] || '').trim() : '',
      fix: 'Add onlyOwner modifier or require(msg.sender == owner) check.',
      fixExplanation: `// ❌ Vulnerable (public function)\nfunction withdraw(uint amount) public {\n    payable(msg.sender).transfer(amount);\n}\n\n// ✅ Fixed (with require)\nfunction withdraw(uint amount) public {\n    require(msg.sender == owner, "Not owner");\n    payable(msg.sender).transfer(amount);\n}`,
      simulation: [
        `1️⃣ Attacker sees public \`${funcNode.name || 'function'}\` without access checks`,
        `2️⃣ Attacker calls \`${funcNode.name || 'function'}\` to ${severity === 'CRITICAL' ? 'drain contract funds' : 'modify critical state'}`,
        `3️⃣ Contract executes the logic because it does not verify msg.sender`,
        `4️⃣ Attacker successfully manipulates contract or drains funds`,
        `5️⃣ True owner loses control of the contract`
      ],
      impact: severity === 'CRITICAL' 
        ? 'CRITICAL: Anyone can drain the contract or destroy it.'
        : 'HIGH: Any address can call critical functions. Unauthorized state manipulation possible.'
    });
  }
});

  return vulnerabilities;
}

module.exports = {
  detect
};

