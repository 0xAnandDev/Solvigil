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

  function validateExploitability(details) {
    if (details.inTryCatch) return "Not exploitable";
    if (details.isChecked) return "Not exploitable";
    return "Exploitable";
  }

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
          let transfersValue = false;
          let queue = [node.expression];
          while (queue.length > 0) {
            let n = queue.pop();
            if (!n) continue;
            if (n.type === 'NameValueList' && n.names && n.names.includes('value')) transfersValue = true;
            if (n.type === 'MemberAccess' && ['send', 'transfer'].includes(n.memberName)) transfersValue = true;
            for (let key in n) {
              if (n[key] && typeof n[key] === 'object' && key !== 'loc') {
                queue.push(n[key]);
              }
            }
          }
          
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

          // Check for try-catch block
          let inTryCatch = false;
          for (let i = parents.length - 1; i >= 0; i--) {
            if (parents[i].type === 'TryStatement') {
              inTryCatch = true;
              break;
            }
          }

          let funcName = 'function';
          for (let i = parents.length - 1; i >= 0; i--) {
            if (parents[i].type === 'FunctionDefinition') {
              funcName = parents[i].name || 'fallback/receive';
              break;
            }
          }
          
          let targetVarName = 'external address';
          if (node.expression && node.expression.expression && node.expression.expression.name) {
            targetVarName = node.expression.expression.name;
          }

          let conditionsVerified = 1; // 1. .call() found
          if (!isChecked) conditionsVerified++; // 2. Return value NOT in require()
          if (!inTryCatch) conditionsVerified++; // 3. NOT in try-catch

          const validation = validateExploitability({
            isChecked,
            inTryCatch
          });

          if (isExternal && validation === "Exploitable") {
            let severity = transfersValue ? 'HIGH' : 'MEDIUM';
            
            // Deterministic Confidence Scoring
            let confidence = 'LOW';
            if (conditionsVerified === 3) confidence = 'HIGH';
            else if (conditionsVerified === 2) confidence = 'MEDIUM';



            const line = node.loc ? node.loc.start.line : 0;
            const column = node.loc ? node.loc.start.column : 0;
            const sourceCode = getSourceLine(line, code) || '';

            vulnerabilities.push({
              type: 'Unchecked External Call',
              severity: severity,
              confidence: confidence,
              line: line,
              column: column,
              description: 'External call return value not checked. Call failure is ignored.',
              code: sourceCode.trim(),
              fix: 'Check the return value or wrap in require().',
              simulation: [
                `1️⃣ \`${funcName}\` makes call to \`${targetVarName}\``,
                `2️⃣ External call to \`${targetVarName}\` fails or throws`,
                `3️⃣ Return value is false/reverts`,
                `4️⃣ \`${funcName}\` ignores the failure`,
                `5️⃣ Logic continues as if call succeeded, leaving state inconsistent`
              ],
              fixExplanation: '❌ Unchecked Call:\n```solidity\ncontractAddress.call{value: 1 ether}("");\n```\n\n✅ Checked Call:\n```solidity\n(bool success, ) = contractAddress.call{value: 1 ether}("");\nrequire(success, "Call failed");\n```',
              impact: severity === 'HIGH' ? 'HIGH: Failed external calls are silently ignored. Contract state may be inconsistent causing significant fund loss.' : 'MEDIUM: Call failure is ignored, but it does not immediately break contract state.'
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
