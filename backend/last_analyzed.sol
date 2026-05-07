// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0; // ❌ Old version (no built-in overflow protection)

contract OldVersion {
    uint8 public value = 255;

    function overflow() public {
        value = value + 1; // ❌ Overflow: becomes 0
    }
}