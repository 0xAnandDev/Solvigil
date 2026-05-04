const { getSourceLine } = require('../ast-builder');

/**
 * Detects Solidity Version Risk by checking for old compiler versions.
 * 
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of vulnerabilities found.
 */
function detect(ast, code, versionStr) {
  const vulnerabilities = [];
  
  if (!versionStr) return vulnerabilities;
  
  let minor = 8;
  let patch = 0;
  
  const parts = versionStr.replace(/[^0-9.]/g, '').split('.');
  if (parts.length >= 2) {
    minor = parseInt(parts[1], 10);
    patch = parts.length >= 3 ? parseInt(parts[2], 10) : 0;
  }

  let isVersionRisk = false;
  let isWarning = false;

  if (minor < 7 || (minor === 7 && patch <= 5)) {
    isVersionRisk = true;
  } else if (minor === 7 && patch >= 6) {
    isWarning = true;
  }

  if (isVersionRisk || isWarning) {
    let pragmaLine = 0;
    let pragmaCol = 0;
    
    function findPragma(node) {
      if (Array.isArray(node)) node.forEach(findPragma);
      else if (node && typeof node === 'object') {
        if (node.type === 'PragmaDirective' && node.name === 'solidity') {
          if (node.loc) {
             pragmaLine = node.loc.start.line;
             pragmaCol = node.loc.start.column;
          }
        }
        for (const key in node) {
          if (key !== 'loc' && typeof node[key] === 'object') findPragma(node[key]);
        }
      }
    }
    findPragma(ast);

    const sourceCode = getSourceLine(pragmaLine, code) || '';
    
    vulnerabilities.push({
      type: 'Solidity Version Risk',
      severity: 'LOW',
      category: 'Best Practice',
      confidence: 'HIGH',
      line: pragmaLine,
      column: pragmaCol,
      description: isVersionRisk 
        ? 'Using deprecated Solidity version. Missing critical safety features like overflow protection.'
        : 'Using older Solidity version (warning). Consider upgrading to 0.8.0+ for better safety and optimizations.',
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
      impact: isVersionRisk ? 'LOW: Old versions lack modern safety features. Contains known bugs.' : 'LOW: Missing latest compiler optimizations and features.'
    });
  }

  return vulnerabilities;
}

module.exports = { detect };
