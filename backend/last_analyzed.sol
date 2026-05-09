// Save as: test-access-control.sol
pragma solidity ^0.8.0;

contract VulnerableContract {
    function withdraw() public {
        msg.sender.transfer(address(this).balance);  // ← No permission check
    }
}