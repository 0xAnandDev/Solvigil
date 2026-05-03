const parser = require('@solidity-parser/parser');

/**
 * Parses Solidity source code and returns the AST.
 * @param {string} code - The Solidity source code.
 * @returns {object} The parsed AST.
 */
function parse(code) {
  try {
    // Parse with location information for vulnerability reporting
    return parser.parse(code, { loc: true });
  } catch (err) {
    // Handle parse errors gracefully
    if (err.errors && err.errors.length > 0) {
      const firstError = err.errors[0];
      throw new Error(`Parse error on line ${firstError.line}: ${firstError.message}`);
    }
    throw new Error('Failed to parse Solidity code: ' + (err.message || 'Unknown error'));
  }
}

/**
 * Extracts high-level information from the AST and source code.
 * @param {object} ast - The parsed AST.
 * @param {string} code - The original Solidity source code.
 * @returns {object} Information object containing contractName, pragma, etc.
 */
function extractInfo(ast, code) {
  let contractName = null;
  let pragma = null;
  let functionCount = 0;
  let stateVariablesCount = 0;

  if (ast) {
    try {
      parser.visit(ast, {
        ContractDefinition(node) {
          // Prioritize actual contract definitions over interfaces or libraries
          if (node.kind === 'contract' && !contractName) {
            contractName = node.name;
          } else if (!contractName) {
            contractName = node.name; // Fallback to first definition found
          }
        },
        PragmaDirective(node) {
          if (node.name === 'solidity') {
            pragma = node.value;
          }
        },
        FunctionDefinition() {
          functionCount++;
        },
        StateVariableDeclaration(node) {
          if (node.variables) {
            stateVariablesCount += node.variables.length;
          }
        }
      });
    } catch (err) {
      console.error('Error extracting info from AST:', err.message);
    }
  }

  const lineCount = code ? code.split(/\r?\n/).length : 0;

  return {
    contractName: contractName || 'Unknown',
    pragma: pragma || 'Unknown',
    lineCount,
    functionCount,
    stateVariablesCount
  };
}

/**
 * Retrieves a specific line of code from the source string.
 * @param {number} lineNumber - The 1-based line number to extract.
 * @param {string} code - The original Solidity source code.
 * @returns {string|null} The source code line or null if invalid.
 */
function getSourceLine(lineNumber, code) {
  if (!code || !lineNumber) return null;
  const lines = code.split(/\r?\n/);
  
  // AST line numbers are 1-indexed
  if (lineNumber > 0 && lineNumber <= lines.length) {
    return lines[lineNumber - 1];
  }
  
  return null;
}

module.exports = {
  parse,
  extractInfo,
  getSourceLine
};
