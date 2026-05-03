const parser = require('@solidity-parser/parser');
const ast = parser.parse(`
contract Test {
  function withdraw() public {
    address(this).call("");
  }
}
`, { loc: true });
console.log(JSON.stringify(ast.children[0].subNodes[0].body.statements[0], null, 2));
