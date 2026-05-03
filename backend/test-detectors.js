const astBuilder = require('./analyzer/ast-builder');
const reentrancy = require('./analyzer/detectors/reentrancy');
const access = require('./analyzer/detectors/access-control');
const unchecked = require('./analyzer/detectors/unchecked-calls');
const overflow = require('./analyzer/detectors/overflow-underflow');

const testCode = `pragma solidity ^0.6.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw(uint amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}`;

const ast = astBuilder.parse(testCode);
console.log('--- REENTRANCY ---');
console.log(reentrancy.detect(ast, testCode));
console.log('--- ACCESS CONTROL ---');
console.log(access.detect(ast, testCode));
console.log('--- UNCHECKED CALLS ---');
console.log(unchecked.detect(ast, testCode));
console.log('--- OVERFLOW ---');
console.log(overflow.detect(ast, testCode));
