// SPDX-License-Identifier: MIT

// This contract was adapted from OpenZeppelin's ERC1967Proxy and TransparentUpgradeableProxy implementation.
// @ref: @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
// @ref: @openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pragma solidity ^0.8.20;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {ERC1967Utils, StorageSlot} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {IUUPSProxy} from "./IUUPSProxy.sol";

contract UUPSProxy is Proxy {
    using StorageSlot for bytes32;
    using SlotDerivation for bytes32;
    using SlotDerivation for string;

    string internal constant _VERIFICATION_SLOT = "proxy.verifiable";
    string internal constant _SALT = "salt";

    // immutable variable (in bytecode)
    address public immutable verifiableProxyFactory;

    constructor(address _factory) {
        verifiableProxyFactory = _factory;
    }

    /**
     * @dev Initializes the verifiable proxy with an initial implementation specified by `implementation`.
     *
     * If `data` is nonempty, it's used as data in a delegate call to `implementation`. This will typically be an
     * encoded function call, and allows initializing the storage of the proxy like a Solidity constructor.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    function initialize(bytes32 _salt, address implementation, bytes memory data) public payable {
        require(implementation != address(0), "New implementation cannot be the zero address");
        require(_implementation() == address(0), "Already initialized");
        _setSalt(_salt);

        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    function getVerifiableProxySalt() public view returns (bytes32) {
        return _getSalt();
    }

    /**
     * @dev Returns the current implementation address.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by ERC-1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function _implementation() internal view virtual override returns (address) {
        return ERC1967Utils.getImplementation();
    }

    function _getSalt() internal view returns (bytes32) {
        bytes32 baseSlot = _VERIFICATION_SLOT.erc7201Slot();
        return baseSlot.deriveMapping(_SALT).getBytes32Slot().value;
    }

    function _setSalt(bytes32 _salt) internal {
        bytes32 baseSlot = _VERIFICATION_SLOT.erc7201Slot();
        baseSlot.deriveMapping(_SALT).getBytes32Slot().value = _salt;
    }

    receive() external payable {}
}
