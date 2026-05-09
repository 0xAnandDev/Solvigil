// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {

    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Deposit ETH
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ REENTRANCY + UNCHECKED STATE UPDATE
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update → reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        
        // ❌ Unchecked error (no require(success))
        // Ignoring failure

        // State updated AFTER call → vulnerable
        balances[msg.sender] -= amount;
    }

    // ❌ BROKEN ACCESS CONTROL
    function setOwner(address newOwner) public {
        // Anyone can become owner
        owner = newOwner;
    }

    // ❌ UNCHECKED LOW-LEVEL CALL
    function sendEther(address payable recipient, uint256 amount) public {
        // No access control → anyone can drain funds
        (bool success, ) = recipient.call{value: amount}("");
        // ❌ Not checking success
    }

    // ❌ SELFDESTRUCT WITH NO ACCESS CONTROL
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // Helper to check contract balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}