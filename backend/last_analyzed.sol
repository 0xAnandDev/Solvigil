// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCall {
    function sendEther(address payable recipient) public payable {
        // ❌ Return value not checked
        recipient.call{value: msg.value}("");
    }
}