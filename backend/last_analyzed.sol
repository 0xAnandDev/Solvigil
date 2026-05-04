// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DoSVulnerable {
    address[] public users;

    function addUser(address user) public {
        users.push(user);
    }

    function payAll() public payable {
        for (uint i = 0; i < users.length; i++) {
            // ❌ If one transfer fails, entire loop fails
            payable(users[i]).transfer(1 ether);
        }
    }
}