const astBuilder = require('./analyzer/ast-builder');
const testCode = `pragma solidity ^0.6.0; contract Test { mapping(address => uint) public balances; function withdraw(uint amount) public { balances[msg.sender] = 0; } }`;
console.log(JSON.stringify(astBuilder.parse(testCode).children[1].subNodes[1].body.statements[0], null, 2));
