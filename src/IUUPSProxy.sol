// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUUPSProxy {
    function getVerifiableProxySalt() external view returns (bytes32);

    function verifiableProxyFactory() external view returns (address);
}
