// SPDX-License-Identifier: MIT

// This contract was adapted from OpenZeppelin's ERC1967Proxy and TransparentUpgradeableProxy implementation.
// @ref: @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
// @ref: @openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol
pragma solidity ^0.8.20;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";
import {ITransparentVerifiableProxy} from "./ITransparentVerifiableProxy.sol";

contract TransparentVerifiableProxy is Proxy, Initializable {
    using StorageSlot for bytes32;
    using SlotDerivation for bytes32;
    using SlotDerivation for string;

    string internal constant _VERIFICATION_SLOT = "proxy.verifiable";
    string internal constant _SALT = "salt";
    string internal constant _OWNER = "owner";

    // immutable variable (in bytecode)
    address public immutable creator;

    // ### EVENTS
    error ProxyDeniedOwnerAccess();

    constructor(address _creator) {
        creator = _creator;
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
    function initialize(uint256 _salt, address _owner, address implementation, bytes memory data)
        public
        payable
        initializer
    {
        require(msg.sender == creator, "Unauthorized initialization");
        require(implementation != address(0), "New implementation cannot be the zero address");

        bytes32 baseSlot = _VERIFICATION_SLOT.erc7201Slot();
        _setSalt(baseSlot, _salt);
        _setOwner(baseSlot, _owner);

        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    function salt() public view returns (uint256) {
        return _getSalt(_VERIFICATION_SLOT.erc7201Slot());
    }

    function owner() public view returns (address) {
        return _getOwner(_VERIFICATION_SLOT.erc7201Slot());
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

    /**
     * @dev If caller is the cretor, process the call internally, otherwise transparently fallback to the proxy behavior.
     */
    function _fallback() internal virtual override {
        if (msg.sender == creator) {
            if (msg.sig != ITransparentVerifiableProxy.upgradeToAndCall.selector) {
                revert ProxyDeniedOwnerAccess();
            } else {
                _dispatchUpgradeToAndCall();
            }
        } else {
            super._fallback();
        }
    }

    /**
     * @dev Upgrade the implementation of the proxy. See {ERC1967Utils-upgradeToAndCall}.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    function _dispatchUpgradeToAndCall() private {
        (address newImplementation, bytes memory data) = abi.decode(msg.data[4:], (address, bytes));
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }

    function _getSalt(bytes32 baseSlot) internal view returns (uint256) {
        return baseSlot.deriveMapping(_SALT).getUint256Slot().value;
    }

    function _setSalt(bytes32 baseSlot, uint256 _salt) internal {
        baseSlot.deriveMapping(_SALT).getUint256Slot().value = _salt;
    }

    function _getOwner(bytes32 baseSlot) internal view returns (address) {
        return baseSlot.deriveMapping(_OWNER).getAddressSlot().value;
    }

    function _setOwner(bytes32 baseSlot, address _owner) internal {
        baseSlot.deriveMapping(_OWNER).getAddressSlot().value = _owner;
    }

    receive() external payable {}
}
