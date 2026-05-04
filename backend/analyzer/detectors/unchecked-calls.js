const { getSourceLine } = require('../ast-builder');

/**
 * Detects unchecked external calls (.call(), .send(), .delegatecall())
 * where the return value is not checked in a require() or if() statement.
 *
 * @param {object} ast - The parsed Solidity AST.
 * @param {string} code - The original Solidity source code.
 * @returns {Array} List of vulnerabilities found.
 */
function detect(ast, code) {
  const vulnerabilities = [];

  function traverse(node, parents) {
    if (Array.isArray(node)) {
      node.forEach(child => traverse(child, parents));
    } else if (node && typeof node === 'object') {
      
      if (node.type === 'FunctionCall') {
        let current = node.expression;
        let isExternal = false;
        while (current) {
          if (current.type === 'MemberAccess') {
            if (['call', 'send', 'delegatecall'].includes(current.memberName)) {
              isExternal = true;
              break;
            }
            current = current.expression;
          } else if (current.expression) {
            current = current.expression;
          } else {
            break;
          }
        }
        
        // Look for .call(), .send(), or .delegatecall()
        if (isExternal) {
          
          let isChecked = false;
          let inIfStatement = false;
          let inRequireAssert = false;
          let checkedInBlock = false;
          
          // Check parent nodes to see if return value is used
          for (let i = parents.length - 1; i >= 0; i--) {
            const parent = parents[i];
            
            // Is it inside an if() statement?
            if (parent.type === 'IfStatement') {
              isChecked = true;
              inIfStatement = true;
              break;
            }
            
            // Is it inside a require() or assert()?
            if (parent.type === 'FunctionCall' && parent.expression) {
              if (parent.expression.name === 'require' || parent.expression.name === 'assert') {
                isChecked = true;
                inRequireAssert = true;
                break;
              }
            }
            
            // If assigned to a variable, check if there's any require/assert/if in the same block
            if (parent.type === 'Block') {
              const blockStr = JSON.stringify(parent);
              if (blockStr.includes('"name":"require"') || blockStr.includes('"name":"assert"') || blockStr.includes('"type":"IfStatement"')) {
                // Heuristic: It might be checked later in the block
                isChecked = true;
                checkedInBlock = true;
                break;
              }
            }
            
            // Stop looking once we hit the block or function level
            if (parent.type === 'Block' || parent.type === 'FunctionDefinition') {
              break;
            }
          }

          if (!isChecked) {
            // Unchecked call detected
            let conditionsVerified = 1; // Has external call that is not directly wrapped
            // Since isChecked is false, we know it's not wrapped in require, if, or checked in block.
            // Let's add conditions for confidence.
            // Condition 1: External call
            // Condition 2: Not in if statement
            // Condition 3: Not in require/assert
            // Condition 4: Not checked later in block
            
            conditionsVerified += (!inIfStatement ? 1 : 0);
            conditionsVerified += (!inRequireAssert ? 1 : 0);
            conditionsVerified += (!checkedInBlock ? 1 : 0);
            
            let confidence = 'LOW';
            if (conditionsVerified === 4) confidence = 'HIGH';
            else if (conditionsVerified === 3) confidence = 'MEDIUM';
            else confidence = 'LOW';

            const line = node.loc ? node.loc.start.line : 0;
            const column = node.loc ? node.loc.start.column : 0;
            const sourceCode = getSourceLine(line, code) || '';

            vulnerabilities.push({
              type: 'Unchecked External Call',
              severity: 'HIGH',
              confidence: confidence,
              line: line,
              column: column,
              description: 'External call return value not checked. Call failure is ignored.',
              code: sourceCode.trim(),
              fix: 'Check the return value or wrap in require().',
              simulation: [
                '1️⃣ Contract calls external address',
                '2️⃣ External call fails or throws',
                '3️⃣ Return value is false/reverts',
                '4️⃣ Contract ignores the failure',
                '5️⃣ Logic continues as if call succeeded'
              ],
              fixExplanation: '❌ Unchecked Call:\n```solidity\ncontractAddress.call{value: 1 ether}("");\n```\n\n✅ Checked Call:\n```solidity\n(bool success, ) = contractAddress.call{value: 1 ether}("");\nrequire(success, "Call failed");\n```',
              impact: 'HIGH: Failed external calls are silently ignored. Contract state may be inconsistent causing significant fund loss.'
            });
          }
        }
      }

      // Continue traversal
      const newParents = [...parents, node];
      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          traverse(node[key], newParents);
        }
      }
    }
  }

  traverse(ast, []);

  return vulnerabilities;
}

module.exports = { detect };
