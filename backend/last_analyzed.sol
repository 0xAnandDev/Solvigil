// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ❌ Missing access control
    function withdrawAll() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}