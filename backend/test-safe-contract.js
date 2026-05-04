const fs = require('fs');
const parser = require('@solidity-parser/parser');
const scanner = require('./analyzer/vulnerability-scanner');
const ScoreCalculator = require('./analyzer/utils/score-calculator');

const code = `
pragma solidity ^0.8.0;

contract SafeContract {
    mapping(address => uint) public balance;
    
    function withdraw(uint amount) public {
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
`;

try {
  const ast = parser.parse(code, { loc: true });
  const vulnerabilities = scanner.scan(ast, code);
  
  const result = ScoreCalculator.calculate(vulnerabilities);
  
  console.log('--- TEST RESULTS ---');
  console.log(`Vulnerabilities Found: ${vulnerabilities.length}`);
  console.log(JSON.stringify(vulnerabilities, null, 2));
  console.log(`Security Score: ${result.score}`);
  console.log(`Security Status: ${result.status}`);
  
  if (vulnerabilities.length === 0 && result.score >= 95) {
    console.log('✅ PASS: Safe contract was correctly identified as safe.');
  } else {
    console.log('❌ FAIL: Safe contract was flagged with vulnerabilities.');
  }
} catch (e) {
  console.error('Error parsing or scanning:', e);
}
