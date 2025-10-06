// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UUPSProxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {
    ERC1967Utils
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";

contract MockProxyAuthorization is IProxyAuthorization, Ownable {
    address allowedPreviousImpl;

    constructor(
        address initialOwner,
        address allowedPreviousImpl_
    ) Ownable(initialOwner) {
        allowedPreviousImpl = allowedPreviousImpl_;
    }

    function isAuthorizedToUpgrade(
        address caller
    ) external view returns (bool) {
        return owner() == caller;
    }

    function canUpgradeFrom(
        address previousImplementation
    ) external view returns (bool) {
        return previousImplementation == allowedPreviousImpl;
    }
}

contract MaliciousProxyAuthorization is IProxyAuthorization, Ownable {
    constructor(address initialOwner) Ownable(initialOwner) {}

    function isAuthorizedToUpgrade(
        address caller
    ) external view returns (bool) {
        return true;
    }

    function canUpgradeFrom(
        address previousImplementation
    ) external view returns (bool) {
        return true;
    }

    function changeImplementation(address newImplementation) external {
        StorageSlot
            .getAddressSlot(ERC1967Utils.IMPLEMENTATION_SLOT)
            .value = newImplementation;
    }
}

contract UUPSProxyTest is Test {
    using StorageSlot for bytes32;
    using SlotDerivation for string;

    UUPSProxy proxy;
    MockProxyAuthorization mockProxyAuthorization;
    MaliciousProxyAuthorization maliciousProxyAuthorization;

    address factory = address(0x1);
    address owner = address(0x2);
    address implementation = address(new MockRegistry());
    bytes32 salt = bytes32(uint256(12345));
    bytes emptyData;

    string internal constant _SALT_SLOT = "eth.ens.proxy.verifiable.salt";

    function setUp() public {
        proxy = new UUPSProxy(factory, salt);
        mockProxyAuthorization = new MockProxyAuthorization(
            owner,
            address(implementation)
        );
        maliciousProxyAuthorization = new MaliciousProxyAuthorization(owner);
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
        assertEq(
            proxy.getVerifiableProxySalt(),
            computedSalt,
            "Salt update failed"
        );
    }

    function testUpgradeToAndCall() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(
            implementation,
            abi.encodeWithSelector(MockRegistry.initialize.selector, owner)
        );
        vm.stopPrank();

        console.logAddress(MockRegistry(address(proxy)).owner());

        // upgrade to proxy authorization
        vm.prank(owner);
        proxy.upgradeToAndCall(address(mockProxyAuthorization), emptyData);

        // verify the upgrade
        assertEq(
            vm.load(address(proxy), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(mockProxyAuthorization)))),
            "Upgrade failed"
        );
    }

    function testUpgradeToAndCall_Malicious() public {
        vm.prank(factory);
        proxy.initialize(address(mockProxyAuthorization), emptyData);

        // upgrade to malicious proxy authorization
        vm.prank(owner);
        vm.expectRevert();
        proxy.upgradeToAndCall(address(maliciousProxyAuthorization), emptyData);
    }

    function testChangeImplementation() public {
        vm.prank(factory);
        proxy.initialize(address(mockProxyAuthorization), emptyData);

        // change the implementation
        vm.prank(owner);
        vm.expectRevert();
        MaliciousProxyAuthorization(address(proxy)).changeImplementation(
            address(implementation)
        );
    }
}
