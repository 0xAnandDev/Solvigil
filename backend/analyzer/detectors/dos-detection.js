const { getSourceLine } = require('../ast-builder');

/**
 * Detects Denial of Service (DoS) vulnerabilities caused by external calls within loops.
 * 
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of vulnerabilities found.
 */
function detect(ast, code) {
  const vulnerabilities = [];

  function validateExploitability(details) {
    // Question 1: Can this actually be exploited?
    if (!details.isUnbounded) return "Not exploitable";

    return "Exploitable";
  }

  function traverse(node, funcName) {
    if (Array.isArray(node)) {
      node.forEach(child => traverse(child, funcName));
    } else if (node && typeof node === 'object') {
      let currentFuncName = funcName || 'function';
      if (node.type === 'FunctionDefinition') {
        currentFuncName = node.name || 'fallback/receive';
      }
      
      if (node.type === 'ForStatement' || node.type === 'WhileStatement') {
        const bodyStr = JSON.stringify(node.body || {});
        const conditionStr = JSON.stringify(node.condition || node.test || {});
        
        const hasFunctionCall = bodyStr.includes('"type":"FunctionCall"');
        const hasExternalMethod = bodyStr.includes('"memberName":"call"') || 
                                  bodyStr.includes('"memberName":"transfer"') || 
                                  bodyStr.includes('"memberName":"send"');

        // --- EXPLOITABILITY CHECK ---
        let isExploitable = true;

        // 1. Is the loop unbounded? (Check for reachable exploit)
        const isUnbounded = conditionStr.includes('"memberName":"length"') || conditionStr.includes('"type":"Identifier"');
        if (!isUnbounded) isExploitable = false;

        // 2. Are there guards/mitigations? (e.g. failure breaks transaction)
        const failureBreaks = bodyStr.includes('"memberName":"transfer"') || bodyStr.includes('"name":"require"');
        if (!failureBreaks) isExploitable = false;

        let externalCallLine = 0;
        let externalCallCol = 0;

        parser.visit(node.body || node, {
          FunctionCall(callNode) {
            if (callNode.expression && callNode.expression.type === 'MemberAccess') {
              const memberName = callNode.expression.memberName;
              if (['call', 'transfer', 'send'].includes(memberName)) {
                if (!externalCallLine && callNode.loc) {
                  externalCallLine = callNode.loc.start.line;
                  externalCallCol = callNode.loc.start.column;
                }
              }
            }
          }
        });

        const validation = validateExploitability({
          isUnbounded,
          failureBreaks
        });

        if (hasFunctionCall && hasExternalMethod && validation === "Exploitable") {
          let conditionsVerified = 1; // Loop found
          if (hasExternalMethod) conditionsVerified++; // External call found
          if (isUnbounded) conditionsVerified++; // Unbounded loop

          let severity = failureBreaks ? 'HIGH' : 'MEDIUM';
          
          // Deterministic Confidence Scoring
          let confidence = 'LOW';
          if (conditionsVerified === 3) confidence = 'HIGH';
          else if (conditionsVerified === 2) confidence = 'MEDIUM';

          const line = externalCallLine || (node.loc ? node.loc.start.line : 0);
          const column = externalCallCol || (node.loc ? node.loc.start.column : 0);
          const sourceCode = getSourceLine(line, code) || '';

          vulnerabilities.push({
            type: 'Denial of Service (DoS)',
            severity: severity,
            category: 'Logic Error',
            confidence: confidence,
            line: line,
            column: column,
            description: 'Loop contains external calls. A single failure will revert entire transaction, causing DoS.',
            code: sourceCode.trim(),
            fix: 'Use pull pattern instead of push. Let users withdraw funds individually.',
            simulation: [
              `1️⃣ \`${currentFuncName}\` loops through recipients`,
              `2️⃣ Sends funds to each one`,
              `3️⃣ One recipient rejects the transfer`,
              `4️⃣ Entire transaction reverts`,
              `5️⃣ No one receives funds (DoS)`
            ],
            fixExplanation: '❌ Vulnerable Code (Push Pattern):\n```solidity\nfunction distributeFunds(address[] memory recipients, uint256[] memory amounts) public {\n    for (uint i = 0; i < recipients.length; i++) {\n        // If one transfer fails, the entire loop reverts\n        payable(recipients[i]).transfer(amounts[i]);\n    }\n}\n```\n\n✅ Safe Code (Pull Pattern):\n```solidity\nmapping(address => uint256) public balances;\n\nfunction allocateFunds(address[] memory recipients, uint256[] memory amounts) public {\n    for (uint i = 0; i < recipients.length; i++) {\n        balances[recipients[i]] += amounts[i];\n    }\n}\n\nfunction withdraw() public {\n    uint256 amount = balances[msg.sender];\n    require(amount > 0, "No funds to withdraw");\n    balances[msg.sender] = 0;\n    payable(msg.sender).transfer(amount);\n}\n```',
            impact: severity === 'HIGH' ? 'HIGH: Contract functionality can be blocked by a single failing external call. Prevents legitimate operations.' : 'MEDIUM: External call in unbounded loop can cause out-of-gas errors, preventing execution.'
          });
        }
      }

      // Continue traversal
      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          traverse(node[key], currentFuncName);
        }
      }
    }
  }

  traverse(ast, 'contract');

  return vulnerabilities;
}

module.exports = { detect };
