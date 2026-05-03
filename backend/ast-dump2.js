const astBuilder = require('./analyzer/ast-builder');
const testCode = `pragma solidity ^0.6.0; contract Test { mapping(address => uint) public balances; function withdraw(uint amount) public { (bool success, ) = msg.sender.call{value: amount}(""); balances[msg.sender] -= amount; } }`;
const ast = astBuilder.parse(testCode);
const fs = require('fs');
fs.writeFileSync('ast.json', JSON.stringify(ast, null, 2), 'utf8');
