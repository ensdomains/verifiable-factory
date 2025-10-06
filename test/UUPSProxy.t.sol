// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UUPSProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";
import {IUUPSProxy} from "../src/IUUPSProxy.sol";

contract MockProxyAuthorization is IProxyAuthorization, OwnableUpgradeable, UUPSUpgradeable {
    address allowedPreviousImpl;

    constructor(address allowedPreviousImpl_) {
        allowedPreviousImpl = allowedPreviousImpl_;
    }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function canUpgradeFrom(address previousImplementation) external view returns (bool) {
        return previousImplementation == allowedPreviousImpl;
    }
}

contract MaliciousProxyAuthorization is IProxyAuthorization, UUPSUpgradeable {
    constructor() {}

    function initialize() public initializer {
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override {}

    function canUpgradeFrom(address previousImplementation) external view returns (bool) {
        return true;
    }

    function changeImplementation(address newImplementation) external {
        StorageSlot.getAddressSlot(ERC1967Utils.IMPLEMENTATION_SLOT).value = newImplementation;
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
    address maliciousUser = address(0x3);
    address implementation = address(new MockRegistry());
    bytes32 salt = bytes32(uint256(12345));
    bytes emptyData;

    string internal constant _SALT_SLOT = "eth.ens.proxy.verifiable.salt";

    function setUp() public {
        proxy = new UUPSProxy(factory, salt);
        mockProxyAuthorization = new MockProxyAuthorization(address(implementation));
        maliciousProxyAuthorization = new MaliciousProxyAuthorization();
    }

    function test_Initialize() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(implementation, abi.encodeWithSelector(MockRegistry.initialize.selector, owner));

        // check salt and owner values
        (bytes32 actualSalt, address actualImplementation) = proxy.getVerifiableProxyData();
        assertEq(actualSalt, salt, "Salt mismatch");
        assertEq(actualImplementation, implementation, "Implementation mismatch");
        assertEq(MockRegistry(address(proxy)).owner(), owner, "Owner mismatch");
    }

    function test_Initialize_ZeroAddress() public {
        vm.prank(factory);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.ImplementationCannotBeZeroAddress.selector));
        proxy.initialize(address(0), emptyData);
    }

    function test_Initialize_AlreadyInitialized() public {
        vm.prank(factory);
        proxy.initialize(implementation, abi.encodeWithSelector(MockRegistry.initialize.selector, owner));

        vm.prank(factory);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.AlreadyInitialized.selector));
        proxy.initialize(implementation, emptyData);
    }

    function test_SaltStorage() public {
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
        (bytes32 actualSalt,) = proxy.getVerifiableProxyData();
        assertEq(actualSalt, computedSalt, "Salt update failed");
    }

    function test_UpgradeToAndCall() public {
        // initialize the proxy
        vm.prank(factory);
        proxy.initialize(implementation, abi.encodeWithSelector(MockRegistry.initialize.selector, owner));

        // upgrade to proxy authorization
        vm.prank(owner);
        proxy.upgradeToAndCall(address(mockProxyAuthorization), emptyData);

        // verify the upgrade
        (, address actualImplementation) = proxy.getVerifiableProxyData();
        assertEq(actualImplementation, address(mockProxyAuthorization), "Upgrade failed");
    }

    function test_UpgradeToAndCall_ZeroAddress() public {
        vm.prank(factory);
        proxy.initialize(implementation, abi.encodeWithSelector(MockRegistry.initialize.selector, owner));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.ImplementationCannotBeZeroAddress.selector));
        proxy.upgradeToAndCall(address(0), emptyData);
    }

    function test_UpgradeToAndCall_ImplementationNotSet() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.ImplementationNotSet.selector));
        proxy.upgradeToAndCall(address(mockProxyAuthorization), emptyData);
    }

    function test_UpgradeToAndCall_UnauthorizedUpgrade() public {
        vm.prank(factory);
        proxy.initialize(
            address(mockProxyAuthorization), abi.encodeWithSelector(MockRegistry.initialize.selector, owner)
        );

        vm.prank(maliciousUser);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, maliciousUser));
        proxy.upgradeToAndCall(address(maliciousProxyAuthorization), emptyData);
    }

    function test_UpgradeToAndCall_InvalidUpgradeTargetForCurrentImplementation() public {
        vm.prank(factory);
        proxy.initialize(address(maliciousProxyAuthorization), emptyData);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.InvalidUpgradeTargetForCurrentImplementation.selector));
        proxy.upgradeToAndCall(
            address(mockProxyAuthorization), abi.encodeWithSelector(MockRegistry.initialize.selector, owner)
        );
    }

    function test_UpgradeNotAllowedInContext() public {
        vm.prank(factory);
        proxy.initialize(address(maliciousProxyAuthorization), emptyData);

        // change the implementation
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IUUPSProxy.UpgradeNotAllowedInContext.selector));
        MaliciousProxyAuthorization(address(proxy)).changeImplementation(address(implementation));
    }
}
