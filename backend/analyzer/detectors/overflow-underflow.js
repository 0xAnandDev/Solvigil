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
function detect(ast, code) {
  const vulnerabilities = [];
  let isOldSolidity = false;

  // First pass: Check pragma directive to determine Solidity version
  function checkPragma(node) {
    if (Array.isArray(node)) {
      node.forEach(checkPragma);
    } else if (node && typeof node === 'object') {
      if (node.type === 'PragmaDirective' && node.name === 'solidity') {
        const val = node.value || '';
        // Check for common pre-0.8.0 patterns
        if (val.includes('0.4') || val.includes('0.5') || val.includes('0.6') || val.includes('0.7')) {
          isOldSolidity = true;
        }
      }
      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          checkPragma(node[key]);
        }
      }
    }
  }

  checkPragma(ast);

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
  function traverse(node, inUnchecked, paramNames) {
    if (Array.isArray(node)) {
      node.forEach(child => traverse(child, inUnchecked, paramNames));
    } else if (node && typeof node === 'object') {
      
      let currentParamNames = paramNames || [];
      if (node.type === 'FunctionDefinition') {
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
          let conditionsVerified = 1; // Condition 1: Arithmetic operation
          conditionsVerified++; // Condition 2: No built-in protection (isOldSolidity || currentlyUnchecked)
          
          if (!isUserSpecificTarget(node, currentParamNames)) {
            conditionsVerified++; // Condition 3: Affects global state / not user specific
          }
          
          const isAssignment = node.type === 'Assignment' || (node.operator && node.operator.includes('=')) || ['++', '--'].includes(node.operator);
          if (isAssignment) {
            conditionsVerified++; // Condition 4: The value is actually stored/assigned
          }

          if (conditionsVerified === 4) {
            let confidence = 'HIGH';

            const line = node.loc ? node.loc.start.line : 0;
            const column = node.loc ? node.loc.start.column : 0;
            const sourceCode = getSourceLine(line, code) || '';
            
            let severity = currentlyUnchecked ? 'MEDIUM' : 'HIGH';
            if (isUserSpecificTarget(node, currentParamNames)) {
              severity = 'LOW';
            }

            let impact = currentlyUnchecked 
              ? 'MEDIUM: Unchecked block disables overflow protection. Values wrap unexpectedly.'
              : 'HIGH: Old Solidity versions lack overflow protection. Values wrap unexpectedly.';
            if (severity === 'LOW') impact = 'LOW: Arithmetic operation lacks overflow protection, but only affects user-specific state.';

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
                '1️⃣ Arithmetic operation encounters maximum value',
                '2️⃣ No overflow protection in old Solidity',
                '3️⃣ Value wraps around to 0 or negative',
                '4️⃣ Contract state corrupted',
                '5️⃣ Funds can be stolen or locked'
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
          traverse(node[key], currentlyUnchecked, currentParamNames);
        }
      }
    }
  }

  traverse(ast, false, []);

  return vulnerabilities;
}

module.exports = { detect };
