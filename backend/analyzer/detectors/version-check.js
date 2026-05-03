const { getSourceLine } = require('../ast-builder');

/**
 * Detects Solidity Version Risk by checking for old compiler versions.
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
      
      if (node.type === 'PragmaDirective' && node.name === 'solidity') {
        const val = node.value || '';
        const oldPatterns = ['^0.4', '^0.5', '^0.6', '^0.7', '0.4.', '0.5.', '0.6.', '0.7.'];
        
        const isOldVersion = oldPatterns.some(pattern => val.includes(pattern));

        if (isOldVersion) {
          const line = node.loc ? node.loc.start.line : 0;
          const column = node.loc ? node.loc.start.column : 0;
          const sourceCode = getSourceLine(line, code) || '';

          vulnerabilities.push({
            type: 'Solidity Version Risk',
            severity: 'LOW',
            category: 'Best Practice',
            confidence: 'HIGH',
            line: line,
            column: column,
            description: 'Using old Solidity version which is deprecated. Missing modern safety features and bug fixes.',
            code: sourceCode.trim(),
            fix: 'Upgrade to latest stable Solidity version (0.8.x or higher).',
            simulation: [
              '1️⃣ Contract uses old Solidity compiler',
              '2️⃣ Missing overflow protection',
              '3️⃣ Missing other safety improvements',
              '4️⃣ Known bugs may apply',
              '5️⃣ Community support is limited'
            ],
            fixExplanation: '❌ Vulnerable Code (Old Version):\n```solidity\npragma solidity ^0.6.0;\n```\n\n✅ Safe Code (Modern Version):\n```solidity\npragma solidity ^0.8.19;\n```',
            impact: 'Old versions lack modern safety features. May contain known bugs and vulnerabilities.'
          });
        }
      }

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
