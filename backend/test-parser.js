const astBuilder = require('./analyzer/ast-builder');
const scanner = require('./analyzer/vulnerability-scanner');
const score = require('./analyzer/utils/score-calculator');
const fs = require('fs');

const testCode = `
pragma solidity ^0.6.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw(uint amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}`;

try {
  console.log('--- AST BUILDER ---');
  const ast = astBuilder.parse(testCode);
  console.log('AST parsed successfully. Node type:', ast.type);
  const info = astBuilder.extractInfo(ast, testCode);
  console.log('Contract Info:', info);

  console.log('\n--- SCANNER ---');
  const vulns = scanner.scan(ast, testCode);
  console.log('Vulnerabilities found:', JSON.stringify(vulns, null, 2));

  console.log('\n--- SCORE CALCULATOR ---');
  const scoreResult = score.calculate(vulns);
  console.log('Score:', scoreResult.score);
} catch(e) {
  console.error('Error:', e);
}
