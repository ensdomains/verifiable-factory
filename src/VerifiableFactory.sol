// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console} from "forge-std/console.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {TransparentVerifiableProxy} from "./TransparentVerifiableProxy.sol";
import {ITransparentVerifiableProxy} from "./ITransparentVerifiableProxy.sol";

contract VerifiableFactory {
    event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation);

    /**
     * @dev Deploys a new `TransparentVerifiableProxy` contract at a deterministic address.
     *
     * This function deploys a proxy contract using the CREATE2 opcode, ensuring a predictable
     * address based on the sender's address and a provided salt. The deployed proxy is
     * controlled by the factory and is initialized to use a specific implementation.
     *
     * - A unique address for the proxy is generated using the caller's address and the salt.
     * - After deployment, the proxy's `initialize` function is called to configure it with the given salt,
     *   the factory address, and the provided implementation address.
     * - The proxy is fully managed by the factory, which controls upgrades and other administrative methods.
     * - The event `ProxyDeployed` is emitted, logging details of the deployment including the sender, proxy address, salt, and implementation.
     *
     * @param implementation The address of the contract implementation the proxy will delegate calls to.
     * @param salt A value provided by the caller to ensure uniqueness of the proxy address.
     * @return proxy The address of the deployed `TransparentVerifiableProxy`.
     */
    function deployProxy(address implementation, uint256 salt, bytes memory data) external returns (address) {
        bytes32 outerSalt = keccak256(abi.encode(msg.sender, salt));

        TransparentVerifiableProxy proxy = new TransparentVerifiableProxy{salt: outerSalt}(address(this));

        require(isContract(address(proxy)), "Proxy deployment failed");

        proxy.initialize(salt, msg.sender, implementation, data);

        emit ProxyDeployed(msg.sender, address(proxy), salt, implementation);
        return address(proxy);
    }

    // Function to upgrade the proxy's implementation (only owner of proxy can call this)
    function upgradeImplementation(address proxyAddress, address newImplementation, bytes memory data) external {
        address owner = ITransparentVerifiableProxy(proxyAddress).getVerifiableProxyOwner();
        require(owner == msg.sender, "Only the owner can upgrade");

        // Upgrade the proxy to point to the new implementation
        ITransparentVerifiableProxy(payable(proxyAddress)).upgradeToAndCall(newImplementation, data);
    }

    /**
     * @dev Initiates verification of a proxy contract.
     *
     * This function attempts to validate a proxy contract by retrieving its salt
     * and reconstructing the address to ensure it was correctly deployed by the
     * current factory.
     *
     * @param proxy The address of the proxy contract being verified.
     * @return A boolean indicating whether the verification succeeded.
     */
    function verifyContract(address proxy) public view returns (bool) {
        if (!isContract(proxy)) {
            return false;
        }
        try ITransparentVerifiableProxy(proxy).getVerifiableProxySalt() returns (uint256 salt) {
            try ITransparentVerifiableProxy(proxy).getVerifiableProxyOwner() returns (address owner) {
                return _verifyContract(proxy, owner, salt);
            } catch {}
        } catch {}

        return false;
    }

    function _verifyContract(address proxy, address owner, uint256 salt) private view returns (bool) {
        // reconstruct the address using CREATE2 and verify it matches
        bytes32 outerSalt = keccak256(abi.encode(owner, salt));

        // get creation bytecode with constructor arguments
        bytes memory bytecode =
            abi.encodePacked(type(TransparentVerifiableProxy).creationCode, abi.encode(address(this)));

        address expectedProxyAddress = Create2.computeAddress(outerSalt, keccak256(bytecode), address(this));

        return expectedProxyAddress == proxy;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
