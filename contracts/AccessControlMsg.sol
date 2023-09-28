pragma solidity ^0.8.0;

// SPDX-License-Identifier: MIT

import 'OpenZeppelin/openzeppelin-contracts@4.8.0/contracts/access/AccessControlEnumerable.sol';

abstract contract AccessControlMsg is AccessControlEnumerable{
    bytes32 public constant MAIN_ADMIN = keccak256('MAIN_ADMIN');
    bytes32 public constant CHILD_ADMIN = keccak256('CHILD_ADMIN');
    bytes32 public constant REQUESTER = keccak256('REQUESTER');


    function _initializeRciAdmin(address admin)
    internal
    {
        _grantRole(MAIN_ADMIN, admin);
        _setRoleAdmin(MAIN_ADMIN, MAIN_ADMIN);

        _grantRole(CHILD_ADMIN, admin);
        _setRoleAdmin(CHILD_ADMIN, MAIN_ADMIN);

        _grantRole(REQUESTER, admin);
        _setRoleAdmin(REQUESTER, CHILD_ADMIN);
    }
}
