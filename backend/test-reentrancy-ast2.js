const parser = require('@solidity-parser/parser');
const ast = parser.parse(`
contract Test {
  function withdraw(uint amount, address to) public nonReentrant {
  }
}
`, { loc: true });
console.log(JSON.stringify(ast.children[0].subNodes[0], null, 2));
