// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UUPSProxy.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";

contract UUPSProxyTest is Test {
    using StorageSlot for bytes32;
    using SlotDerivation for string;

    UUPSProxy proxy;

    address factory = address(0x1);
    address owner = address(0x2);
    address implementation = address(new MockRegistry());
    bytes32 salt = bytes32(uint256(12345));
    bytes emptyData;

    string internal constant _SALT_SLOT = "eth.ens.proxy.verifiable.salt";

    function setUp() public {
        proxy = new UUPSProxy(factory, salt);
    }

    function testInitialize() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(implementation, emptyData);

        // check salt and owner values
        assertEq(proxy.getVerifiableProxySalt(), salt, "Salt mismatch");
    }

    function testSaltStorage() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(implementation, emptyData);

        // use SlotDerivation to compute the salt slot
        bytes32 saltSlot = _SALT_SLOT.erc7201Slot();

        // directly manipulate the storage for the salt
        uint256 newSalt = 54321;
        bytes32 computedSalt = keccak256(abi.encode(owner, newSalt));
        vm.store(address(proxy), saltSlot, computedSalt);

        // verify the updated salt
        assertEq(proxy.getVerifiableProxySalt(), computedSalt, "Salt update failed");
    }
}
