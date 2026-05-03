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
      
      if (node.type === 'ForStatement') {
        const bodyStr = JSON.stringify(node.body || {});
        
        const hasFunctionCall = bodyStr.includes('"type":"FunctionCall"');
        const hasExternalMethod = bodyStr.includes('"memberName":"call"') || 
                                  bodyStr.includes('"memberName":"transfer"') || 
                                  bodyStr.includes('"memberName":"send"');

        if (hasFunctionCall && hasExternalMethod) {
          const line = node.loc ? node.loc.start.line : 0;
          const column = node.loc ? node.loc.start.column : 0;
          const sourceCode = getSourceLine(line, code) || '';

          vulnerabilities.push({
            type: 'Denial of Service',
            severity: 'MEDIUM',
            category: 'Logic Error',
            confidence: 'MEDIUM',
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
