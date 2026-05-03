const astBuilder = require('./analyzer/ast-builder');
const testCode = `pragma solidity ^0.6.0; contract Test { function withdraw(uint amount) public { (bool success, ) = msg.sender.call{value: amount}(""); balances[msg.sender] -= amount; } }`;
console.log(JSON.stringify(astBuilder.parse(testCode), null, 2));
