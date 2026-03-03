// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {UUPSProxy} from "./UUPSProxy.sol";
import {IUUPSProxy} from "./IUUPSProxy.sol";
import {IVerifiableFactory} from "./IVerifiableFactory.sol";

contract VerifiableFactory is IVerifiableFactory {
    /**
     * @dev Deploys a new `UUPSProxy` contract at a deterministic address.
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
     * @return proxy The address of the deployed `UUPSProxy`.
     */
    function deployProxy(address implementation, uint256 salt, bytes memory data) external returns (address) {
        bytes32 outerSalt = keccak256(abi.encode(msg.sender, salt));

        UUPSProxy proxy = new UUPSProxy{salt: outerSalt}(address(this), outerSalt);

        proxy.initialize(implementation, data);

        emit ProxyDeployed(msg.sender, address(proxy), salt, implementation);
        return address(proxy);
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
    function verifyContract(address proxy, address expectedImplementation) public view returns (bool) {
        if (!isContract(proxy)) return false;

        try IUUPSProxy(proxy).getVerifiableProxyData() returns (bytes32 salt, address actualImplementation) {
            if (actualImplementation != expectedImplementation) return false;
            return _verifyContract(proxy, salt);
        } catch {}
        return false;
    }

    function _verifyContract(address proxy, bytes32 salt) private view returns (bool) {
        // get creation bytecode with constructor arguments
        bytes memory bytecode = abi.encodePacked(type(UUPSProxy).creationCode, abi.encode(address(this), salt));

        address expectedProxyAddress = Create2.computeAddress(salt, keccak256(bytecode), address(this));

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
