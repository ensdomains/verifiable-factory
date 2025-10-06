// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUUPSProxy {
    error ImplementationCannotBeZeroAddress();

    error AlreadyInitialized();

    error ImplementationNotSet();

    error InvalidUpgradeTargetForCurrentImplementation();

    error UpgradeNotAllowedInContext();

    function getVerifiableProxySalt() external view returns (bytes32);

    function verifiableProxyFactory() external view returns (address);
}
