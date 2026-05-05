pragma solidity ^0.8.0;
contract Safe {
  uint public counter = 0;
  function increment() public {
    counter++;
  }
}