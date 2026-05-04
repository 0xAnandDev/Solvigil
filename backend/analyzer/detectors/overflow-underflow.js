const { getSourceLine } = require('../ast-builder');
const parser = require('@solidity-parser/parser');

/**
 * Detects Integer Overflow and Underflow vulnerabilities.
 * Checks for:
 * 1. Arithmetic operations in old Solidity versions (< 0.8.0)
 * 2. Arithmetic operations inside unchecked { ... } blocks
 *
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of vulnerabilities found.
 */
function detect(ast, code, version) {
  const vulnerabilities = [];
  let isOldSolidity = false;

  // Check version passed from scanner
  if (version) {
    const parts = version.replace(/[^0-9.]/g, '').split('.');
    if (parts.length >= 2) {
      const minor = parseInt(parts[1], 10);
      if (minor < 8) isOldSolidity = true;
    }
  }

  function isUserSpecificTarget(node, paramNames) {
    if (!node) return false;
    let target = node;
    if (node.type === 'Assignment') target = node.left;
    else if (node.type === 'UnaryOperation') target = node.subExpression;

    let isUser = false;
    parser.visit(target, {
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

  // Second pass: Find arithmetic operations
  function traverse(node, inUnchecked, paramNames, funcName) {
    if (Array.isArray(node)) {
      node.forEach(child => traverse(child, inUnchecked, paramNames, funcName));
    } else if (node && typeof node === 'object') {
      
      let currentParamNames = paramNames || [];
      let currentFuncName = funcName || 'function';
      if (node.type === 'FunctionDefinition') {
        currentFuncName = node.name || 'fallback/receive';
        currentParamNames = [];
        if (node.parameters) {
          node.parameters.forEach(p => {
             if (p.name) currentParamNames.push(p.name);
          });
        }
      }
      
      let currentlyUnchecked = inUnchecked;
      if (node.type === 'UncheckedStatement') {
        currentlyUnchecked = true;
      }

      // Identify arithmetic operations
      const isArithmetic = (
        (node.type === 'BinaryOperation' && ['+', '-', '*', '/', '+=', '-=', '*=', '/='].includes(node.operator)) ||
        (node.type === 'UnaryOperation' && ['+', '-', '++', '--'].includes(node.operator)) ||
        (node.type === 'Assignment' && ['+=', '-=', '*=', '/='].includes(node.operator))
      );

      if (isArithmetic) {
        if (isOldSolidity || currentlyUnchecked) {
          // --- EXPLOITABILITY CHECK ---
          let isExploitable = true;
          
          // 1. Check if the arithmetic operation is actually saved to state
          const isAssignment = node.type === 'Assignment' || (node.operator && node.operator.includes('=')) || ['++', '--'].includes(node.operator);
          if (!isAssignment) isExploitable = false;

          // 2. Check if the operation affects only the user (mitigation reduces severity)
          let isUserSpecific = isUserSpecificTarget(node, currentParamNames);

          if (isExploitable) {
            let severity = 'LOW';
            if (isOldSolidity && !isUserSpecific) {
              severity = 'CRITICAL';
            } else if (currentlyUnchecked) {
              severity = 'MEDIUM';
            } else if (isOldSolidity && isUserSpecific) {
              severity = 'LOW';
            }

            let confidence = severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM';

            const line = node.loc ? node.loc.start.line : 0;
            const column = node.loc ? node.loc.start.column : 0;
            const sourceCode = getSourceLine(line, code) || '';

            let impact = severity === 'CRITICAL' 
              ? 'CRITICAL: Old Solidity versions lack overflow protection. Critical contract state can be corrupted.'
              : (severity === 'MEDIUM' ? 'MEDIUM: Unchecked block disables overflow protection in non-critical function.' : 'LOW: Arithmetic operation lacks overflow protection, but only affects user-specific state.');

            vulnerabilities.push({
              type: 'Integer Overflow/Underflow',
              severity: severity,
              confidence: confidence,
              line: line,
              column: column,
              description: 'Arithmetic operation without overflow protection. Vulnerable to overflow/underflow.',
              code: sourceCode.trim(),
              fix: 'Upgrade to Solidity >=0.8.0 or use OpenZeppelin SafeMath library.',
              simulation: [
                `1️⃣ Arithmetic operation in \`${currentFuncName}\` encounters maximum/minimum value`,
                `2️⃣ No overflow protection present`,
                `3️⃣ Value wraps around to 0 or negative`,
                `4️⃣ Contract state corrupted`,
                `5️⃣ Funds can be stolen or locked`
              ],
              fixExplanation: '❌ Vulnerable Code (pre-0.8.0):\n```solidity\npragma solidity ^0.7.0;\ncontract Token {\n    mapping(address => uint256) public balances;\n    function transfer(address to, uint256 amount) public {\n        balances[msg.sender] -= amount; // No overflow check\n        balances[to] += amount;\n    }\n}\n```\n\n✅ Safe Code (0.8.0+):\n```solidity\npragma solidity ^0.8.0;\ncontract Token {\n    mapping(address => uint256) public balances;\n    function transfer(address to, uint256 amount) public {\n        balances[msg.sender] -= amount; // Automatically checks for overflow/underflow\n        balances[to] += amount;\n    }\n}\n```',
              impact: impact
            });
          }
        }
      }

      // Continue traversal
      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          traverse(node[key], currentlyUnchecked, currentParamNames, currentFuncName);
        }
      }
    }
  }

  traverse(ast, false, [], 'contract');

  return vulnerabilities;
}

module.exports = { detect };
