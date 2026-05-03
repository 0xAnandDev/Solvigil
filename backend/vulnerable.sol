pragma solidity ^0.6.0;
contract Test {
  mapping(address => uint) public balance;
  function withdraw(uint amount) public {
    (bool success, ) = msg.sender.call{value: amount}("");
    balance[msg.sender] -= amount;
  }
}