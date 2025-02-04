// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransparentVerifiableProxy {
    function getVerifiableProxySalt() external view returns (uint256);

    function getVerifiableProxyOwner() external view returns (address);

    function verifiableProxyCreator() external view returns (address);

    /// @dev See {UUPSUpgradeable-upgradeToAndCall}
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}
