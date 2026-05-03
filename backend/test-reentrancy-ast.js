const parser = require('@solidity-parser/parser');
const ast = parser.parse(`
contract Test {
  mapping(address => uint) balances;
  function withdraw(uint amount, address to) public {
    balances[msg.sender] -= amount;
    to.call{value: amount}("");
    balances[msg.sender] -= amount;
  }
}
`, { loc: true });
console.log(JSON.stringify(ast, null, 2));
