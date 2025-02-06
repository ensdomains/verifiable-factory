// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {VerifiableFactory} from "../src/VerifiableFactory.sol";
import {UUPSProxy} from "../src/UUPSProxy.sol";
import {IUUPSProxy} from "../src/IUUPSProxy.sol";
import {MockRegistry} from "../src/mock/MockRegistry.sol";
import {MockRegistryV2} from "../src/mock/MockRegistryV2.sol";

contract VerifiableFactoryTest is Test {
    // contract instances
    VerifiableFactory public factory;
    MockRegistry public implementation;
    MockRegistryV2 public implementationV2;

    // test addresses
    address public owner;
    address public user;
    address public maliciousUser;
    bytes emptyData;

    // ### Events
    event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        maliciousUser = makeAddr("malicious");

        // deploy contracts
        factory = new VerifiableFactory();
        implementation = new MockRegistry();
        implementationV2 = new MockRegistryV2();

        vm.label(address(factory), "Factory");
        vm.label(address(implementation), "Implementation");
        vm.label(address(implementationV2), "ImplementationV2");
    }

    function test_FactoryInitialState() public view {
        assertTrue(address(factory) != address(0), "Factory deployment failed");
        assertTrue(address(implementation) != address(0), "Implementation deployment failed");
    }

    function test_DeployProxy() public {
        uint256 salt = 1;

        // test event emit
        vm.expectEmit(true, true, true, true);
        emit ProxyDeployed(owner, computeExpectedAddress(salt), salt, address(implementation));

        vm.startPrank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, emptyData);

        vm.stopPrank();

        // verify proxy deployment
        assertTrue(proxyAddress != address(0), "Proxy address should not be zero");
        assertTrue(isContract(proxyAddress), "Proxy should be a contract");

        // verify proxy state
        UUPSProxy proxy = UUPSProxy(payable(proxyAddress));
        bytes32 computedSalt = keccak256(abi.encode(owner, salt));
        assertEq(proxy.getVerifiableProxySalt(), computedSalt, "Proxy salt mismatch");
        assertEq(proxy.verifiableProxyFactory(), address(factory), "Proxy factory mismatch");
    }

    function test_DeployProxyWithSameSalt() public {
        uint256 salt = 1;
        vm.startPrank(owner);

        // deploy first proxy
        factory.deployProxy(address(implementation), salt, emptyData);

        // try to deploy another proxy with same salt - should fail
        vm.expectRevert();
        factory.deployProxy(address(implementation), salt, emptyData);

        vm.stopPrank();
    }

    function test_UpgradeImplementation() public {
        uint256 salt = 1;

        bytes memory initData = abi.encodeWithSelector(MockRegistry.initialize.selector, owner);
        // deploy proxy as owner
        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, initData);

        MockRegistry proxyV1 = MockRegistry(proxyAddress);

        // try to upgrade as non-owner (should fail)
        vm.prank(maliciousUser);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, maliciousUser));
        proxyV1.upgradeToAndCall(
            address(implementationV2),
            "" // add upgrade data if we need
        );

        console2.log("proxyV1.owner()");
        console2.logAddress(proxyV1.owner());
        // upgrade as owner (should pass)
        vm.prank(owner);
        proxyV1.upgradeToAndCall(
            address(implementationV2),
            "" // add upgrade data if we need
        );

        // verify new implementation
        MockRegistryV2 upgradedProxy = MockRegistryV2(proxyAddress);
        assertEq(upgradedProxy.getRegistryVersion(), 2, "Implementation upgrade failed");
    }

    function test_VerifyContract() public {
        uint256 salt = 1;

        // deploy proxy
        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, emptyData);

        vm.prank(owner);
        // verify the contract
        bool isVerified = factory.verifyContract(proxyAddress);
        assertTrue(isVerified, "Contract verification failed");

        vm.prank(owner);
        // try to verify non-existent contract
        address randomAddress = makeAddr("random");
        bool shouldBeFalse = factory.verifyContract(randomAddress);
        assertFalse(shouldBeFalse, "Non-existent contract should not verify");
    }

    function test_ProxyInitialization() public {
        uint256 salt = 1;

        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, emptyData);

        // test proxy state
        UUPSProxy proxy = UUPSProxy(payable(proxyAddress));

        bytes32 computedSalt = keccak256(abi.encode(owner, salt));
        assertEq(proxy.getVerifiableProxySalt(), computedSalt, "Wrong salt");
        assertEq(proxy.verifiableProxyFactory(), address(factory), "Wrong factory");
    }

    function test_StoragePersistenceAfterUpgrade() public {
        uint256 salt = 1;
        address testAccount = makeAddr("testAccount");

        bytes memory initData = abi.encodeWithSelector(MockRegistry.initialize.selector, owner);

        // deploy proxy
        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, initData);

        // initialize v1 implementation
        MockRegistry proxyV1 = MockRegistry(proxyAddress);

        assertEq(proxyV1.owner(), owner, "Owner should be set");

        // register an address
        vm.prank(owner);
        proxyV1.register(testAccount);
        assertTrue(proxyV1.registeredAddresses(testAccount), "Address should be registered in V1");
        assertEq(proxyV1.getRegistryVersion(), 1, "Should be V1 implementation");

        // upgrade to v2
        vm.prank(owner);
        proxyV1.upgradeToAndCall(
            address(implementationV2),
            "" // add upgrade data if we need
        );

        // verify state persists after upgrade
        MockRegistryV2 proxyV2 = MockRegistryV2(proxyAddress);

        // check storage persistence
        assertTrue(proxyV2.registeredAddresses(testAccount), "Address registration should persist after upgrade");
        assertEq(proxyV2.owner(), owner, "Owner should persist after upgrade");
        assertEq(proxyV2.getRegistryVersion(), 2, "Should be V2 implementation");

        // verify v2 functionality still works as it should be
        address newTestAccount = makeAddr("newTestAccount");
        vm.prank(owner);
        proxyV2.register(newTestAccount);
        assertTrue(proxyV2.registeredAddresses(newTestAccount), "Should be able to register new address in V2");

        address newTestAccount2 = makeAddr("newTestAccount2");
        vm.prank(maliciousUser);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, maliciousUser));
        proxyV2.register(newTestAccount2);
    }

    function test_ProxyOwner() public {
        uint256 salt = 1;

        bytes memory initData = abi.encodeWithSelector(MockRegistry.initialize.selector, owner);

        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt, initData);

        // test proxy state
        UUPSProxy proxy = UUPSProxy(payable(proxyAddress));
        MockRegistry proxyRegistryV1 = MockRegistry(proxyAddress);

        bytes32 computedSalt = keccak256(abi.encode(owner, salt));
        assertEq(proxy.getVerifiableProxySalt(), computedSalt, "Wrong proxy salt");
        assertEq(proxyRegistryV1.owner(), owner, "Wrong proxyRegistryV1 owner");
        assertEq(proxy.verifiableProxyFactory(), address(factory), "Wrong proxy factory");
    }

    // ### Helpers
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function computeExpectedAddress(uint256 salt) internal view returns (address) {
        bytes32 outerSalt = keccak256(abi.encode(owner, salt));

        bytes memory bytecode = abi.encodePacked(type(UUPSProxy).creationCode, abi.encode(address(factory)));

        return Create2.computeAddress(outerSalt, keccak256(bytecode), address(factory));
    }
}
