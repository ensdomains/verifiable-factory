// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {VerifiableFactory} from "../src/VerifiableFactory.sol";
import {TransparentVerifiableProxy} from "../src/TransparentVerifiableProxy.sol";
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
        address proxyAddress = factory.deployProxy(address(implementation), salt);

        vm.stopPrank();

        // verify proxy deployment
        assertTrue(proxyAddress != address(0), "Proxy address should not be zero");
        assertTrue(isContract(proxyAddress), "Proxy should be a contract");

        // verify proxy state
        TransparentVerifiableProxy proxy = TransparentVerifiableProxy(payable(proxyAddress));
        assertEq(proxy.salt(), salt, "Proxy salt mismatch");
        assertEq(proxy.owner(), owner, "Proxy owner mismatch");
        assertEq(proxy.creator(), address(factory), "Proxy creator mismatch");
    }

    function test_DeployProxyWithSameSalt() public {
        uint256 salt = 1;
        vm.startPrank(owner);

        // deploy first proxy
        factory.deployProxy(address(implementation), salt);

        // try to deploy another proxy with same salt - should fail
        vm.expectRevert();
        factory.deployProxy(address(implementation), salt);

        vm.stopPrank();
    }

    function test_UpgradeImplementation() public {
        uint256 salt = 1;

        // deploy proxy as owner
        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt);

        // try to upgrade as non-owner (should fail)
        vm.prank(maliciousUser);
        vm.expectRevert("Only the owner can upgrade");
        factory.upgradeImplementation(
            proxyAddress,
            address(implementationV2),
            "" // add upgrade data if we need
        );

        // upgrade as owner (should pass)
        vm.prank(owner);
        factory.upgradeImplementation(
            proxyAddress,
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
        address proxyAddress = factory.deployProxy(address(implementation), salt);

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
        address proxyAddress = factory.deployProxy(address(implementation), salt);

        // test proxy state
        TransparentVerifiableProxy proxy = TransparentVerifiableProxy(payable(proxyAddress));

        assertEq(proxy.salt(), salt, "Wrong salt");
        assertEq(proxy.owner(), owner, "Wrong owner");
        assertEq(proxy.creator(), address(factory), "Wrong creator");
    }

    function test_StoragePersistenceAfterUpgrade() public {
        uint256 salt = 1;
        address testAccount = makeAddr("testAccount");

        // deploy proxy
        vm.prank(owner);
        address proxyAddress = factory.deployProxy(address(implementation), salt);

        // initialize v1 implementation
        MockRegistry proxyV1 = MockRegistry(proxyAddress);

        // initialize registry
        vm.prank(owner);
        proxyV1.initialize(owner);
        assertEq(proxyV1.admin(), owner, "Admin should be set");

        // register an address
        vm.prank(owner);
        proxyV1.register(testAccount);
        assertTrue(proxyV1.registeredAddresses(testAccount), "Address should be registered in V1");
        assertEq(proxyV1.getRegistryVersion(), 1, "Should be V1 implementation");

        // upgrade to v2
        vm.prank(owner);
        factory.upgradeImplementation(proxyAddress, address(implementationV2), "");

        // verify state persists after upgrade
        MockRegistryV2 proxyV2 = MockRegistryV2(proxyAddress);

        // check storage persistence
        assertTrue(proxyV2.registeredAddresses(testAccount), "Address registration should persist after upgrade");
        assertEq(proxyV2.admin(), owner, "Admin should persist after upgrade");
        assertEq(proxyV2.getRegistryVersion(), 2, "Should be V2 implementation");

        // verify v2 functionality still works as it should be
        address newTestAccount = makeAddr("newTestAccount");
        vm.prank(owner);
        proxyV2.register(newTestAccount);
        assertTrue(proxyV2.registeredAddresses(newTestAccount), "Should be able to register new address in V2");
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

        bytes memory bytecode =
            abi.encodePacked(type(TransparentVerifiableProxy).creationCode, abi.encode(address(factory)));

        return Create2.computeAddress(outerSalt, keccak256(bytecode), address(factory));
    }
}
