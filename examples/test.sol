// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCall {
    uint256[] private values;
    
    function withdrawBalance(address payable recipient) public {
        // Unchecked call - return value is not verified
        recipient.call{value: address(this).balance}("");
        
        // Using a numeric literal as array index
        values[0] = 100;
        values[1] = 200;
        values[2] = 300;

        
        // The correct way would be:
        // (bool success, ) = recipient.call{value: address(this).balance}("");
        // require(success, "Transfer failed");
    }
} 