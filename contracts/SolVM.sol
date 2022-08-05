// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract SolVM {
  constructor() public {
  }
  /*
    {
      "inputs": [
        {
          "internalType": "bytes",
          "name": "_bytecode",
          "type": "bytes"
        }
      ],
      "name": "executeBytecode",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  */
  function executeBytecode(bytes calldata _bytecode) public {}
}
