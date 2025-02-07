// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UUPSProxy.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";

contract UUPSProxyTest is Test {
    using SlotDerivation for bytes32;

    UUPSProxy proxy;

    address factory = address(0x1);
    address owner = address(0x2);
    address implementation = address(new MockRegistry());
    bytes32 salt = bytes32(uint256(12345));
    bytes emptyData;

    string internal constant _VERIFICATION_SLOT = "proxy.verifiable";
    string internal constant _SALT = "salt";
    string internal constant _OWNER = "owner";

    function setUp() public {
        proxy = new UUPSProxy(factory);
    }

    function testInitialize() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(salt, implementation, emptyData);

        // check salt and owner values
        assertEq(proxy.getVerifiableProxySalt(), salt, "Salt mismatch");
    }

    function testSaltStorage() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(salt, implementation, emptyData);

        // compute the base slot
        bytes32 baseSlot = SlotDerivation.erc7201Slot(_VERIFICATION_SLOT);

        // use SlotDerivation to compute the salt slot
        bytes32 saltSlot = baseSlot.deriveMapping(_SALT);

        // directly manipulate the storage for the salt
        bytes32 newSalt = bytes32(uint256(54321));
        bytes32 computedSalt = keccak256(abi.encode(owner, newSalt));
        vm.store(address(proxy), saltSlot, computedSalt);

        // verify the updated salt
        assertEq(proxy.getVerifiableProxySalt(), computedSalt, "Salt update failed");
    }
}
