// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifiableFactory {
    error VerificationFailed(address proxy);

    event ProxyDeployed(address indexed sender, address indexed proxyAddress, uint256 salt, address implementation);

    function deployProxy(address implementation, uint256 salt, bytes memory data) external returns (address);

    /// @notice Predicts the proxy address for a deployer and user salt, whether or not it is deployed.
    /// @dev The address is independent of the implementation and initialization data.
    /// @param deployer The account that calls deployProxy.
    /// @param salt The user salt passed to deployProxy, before the deployer is mixed in.
    /// @return proxy The predicted proxy address.
    function predictProxyAddress(address deployer, uint256 salt) external view returns (address proxy);

    function verifyContract(address proxy) external view returns (address implementation);
}
