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

  function traverse(node) {
    if (Array.isArray(node)) {
      node.forEach(traverse);
    } else if (node && typeof node === 'object') {
      
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

        let conditionsVerified = 0;
        if (node.type === 'ForStatement' || node.type === 'WhileStatement') conditionsVerified++; // 1. Loop found
        if (hasFunctionCall && hasExternalMethod) conditionsVerified++; // 2. External call/transfer inside loop
        
        if (isUnbounded) conditionsVerified++; // 3. Loop can be long/unbounded
        if (failureBreaks) conditionsVerified++; // 4. Failure breaks transaction

        // Only flag if ACTUALLY exploitable
        if (!isExploitable) conditionsVerified = 0;

        if (conditionsVerified === 4) {
          const line = externalCallLine || (node.loc ? node.loc.start.line : 0);
          const column = externalCallCol || (node.loc ? node.loc.start.column : 0);
          const sourceCode = getSourceLine(line, code) || '';

          vulnerabilities.push({
            type: 'Denial of Service',
            severity: 'MEDIUM',
            category: 'Logic Error',
            confidence: 'HIGH',
            line: line,
            column: column,
            description: 'Loop contains external calls. A single failure will revert entire transaction, causing DoS.',
            code: sourceCode.trim(),
            fix: 'Use pull pattern instead of push. Let users withdraw funds individually.',
            simulation: [
              '1️⃣ Contract loops through recipients',
              '2️⃣ Sends funds to each one',
              '3️⃣ One recipient rejects the transfer',
              '4️⃣ Entire transaction reverts',
              '5️⃣ No one receives funds (DoS)'
            ],
            fixExplanation: '❌ Vulnerable Code (Push Pattern):\n```solidity\nfunction distributeFunds(address[] memory recipients, uint256[] memory amounts) public {\n    for (uint i = 0; i < recipients.length; i++) {\n        // If one transfer fails, the entire loop reverts\n        payable(recipients[i]).transfer(amounts[i]);\n    }\n}\n```\n\n✅ Safe Code (Pull Pattern):\n```solidity\nmapping(address => uint256) public balances;\n\nfunction allocateFunds(address[] memory recipients, uint256[] memory amounts) public {\n    for (uint i = 0; i < recipients.length; i++) {\n        balances[recipients[i]] += amounts[i];\n    }\n}\n\nfunction withdraw() public {\n    uint256 amount = balances[msg.sender];\n    require(amount > 0, "No funds to withdraw");\n    balances[msg.sender] = 0;\n    payable(msg.sender).transfer(amount);\n}\n```',
            impact: 'Contract functionality can be blocked by a single failing external call. Prevents legitimate operations.'
          });
        }
      }

      // Continue traversal
      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          traverse(node[key]);
        }
      }
    }
  }

  traverse(ast);

  return vulnerabilities;
}

module.exports = { detect };
