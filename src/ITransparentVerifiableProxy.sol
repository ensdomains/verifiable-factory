// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransparentVerifiableProxy {
    function salt() external view returns (uint256);

    function owner() external view returns (address);

    function creator() external view returns (address);

    /// @dev See {UUPSUpgradeable-upgradeToAndCall}
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}
