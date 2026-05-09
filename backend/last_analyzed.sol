// Save as: test-reentrancy.sol
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint) public balance;
    
    function withdraw(uint amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balance[msg.sender] -= amount;  // ← Line: State update AFTER call
    }
}