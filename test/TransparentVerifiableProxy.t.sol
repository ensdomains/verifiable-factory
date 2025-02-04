// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TransparentVerifiableProxy.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";

contract TransparentVerifiableProxyTest is Test {
    using SlotDerivation for bytes32;

    TransparentVerifiableProxy proxy;

    address creator = address(0x1);
    address owner = address(0x2);
    address implementation = address(new MockRegistry());
    uint256 salt = 12345;
    bytes emptyData;

    string internal constant _VERIFICATION_SLOT = "proxy.verifiable";
    string internal constant _SALT = "salt";
    string internal constant _OWNER = "owner";

    function setUp() public {
        proxy = new TransparentVerifiableProxy(creator);
    }

    function testInitialize() public {
        // initialize the proxy
        vm.prank(creator);
        proxy.initialize(salt, owner, implementation, emptyData);

        // check salt and owner values
        assertEq(proxy.salt(), salt, "Salt mismatch");
        assertEq(proxy.owner(), owner, "Owner mismatch");
    }

    function testSaltStorage() public {
        // initialize the proxy
        vm.prank(creator);
        proxy.initialize(salt, owner, implementation, emptyData);

        // compute the base slot
        bytes32 baseSlot = SlotDerivation.erc7201Slot(_VERIFICATION_SLOT);

        // use SlotDerivation to compute the salt slot
        bytes32 saltSlot = baseSlot.deriveMapping(_SALT);

        // directly manipulate the storage for the salt
        uint256 newSalt = 54321;
        vm.store(address(proxy), saltSlot, bytes32(newSalt));

        // verify the updated salt
        assertEq(proxy.salt(), newSalt, "Salt update failed");
    }

    function testOwnerStorage() public {
        // initialize the proxy
        vm.prank(creator);
        proxy.initialize(salt, owner, implementation, emptyData);

        // compute the base slot
        bytes32 baseSlot = SlotDerivation.erc7201Slot(_VERIFICATION_SLOT);

        // use SlotDerivation to compute the owner slot
        bytes32 ownerSlot = baseSlot.deriveMapping(_OWNER);

        // directly manipulate the storage for the owner
        address newOwner = address(0x4);
        vm.store(address(proxy), ownerSlot, bytes32(uint256(uint160(newOwner))));

        // verify the updated owner
        assertEq(proxy.owner(), newOwner, "Owner update failed");
    }
}
