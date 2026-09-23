// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifiableFactory {
    error VerificationFailed(address proxy);

    event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation);

    function deployProxy(address implementation, uint256 salt, bytes memory data) external returns (address);

    function predictProxyAddress(address deployer, uint256 salt) external view returns (address proxy);

    function verifyContract(address proxy) external view returns (address implementation);
}
