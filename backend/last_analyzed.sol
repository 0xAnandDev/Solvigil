// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract OverflowUnderflow {
    uint256 public count = 0;

    function decrement() public {
        count--; // ❌ Underflow: becomes very large number
    }

    function increment() public {
        count++; // ❌ Overflow possible
    }
}   