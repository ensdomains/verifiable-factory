// SPDX-License-Identifier: MIT

// This contract was adapted from OpenZeppelin's ERC1967Proxy and UUPS proxy pattern.
// @ref: @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
// @ref: @openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol
pragma solidity ^0.8.20;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {ERC1967Utils, StorageSlot} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {SlotDerivation} from "@openzeppelin/contracts/utils/SlotDerivation.sol";

import {IProxyAuthorization} from "./IProxyAuthorization.sol";
import {IUUPSProxy} from "./IUUPSProxy.sol";

contract UUPSProxy is Proxy, IUUPSProxy {
    using StorageSlot for bytes32;
    using SlotDerivation for string;

    string internal constant _SALT_SLOT = "eth.ens.proxy.verifiable.salt";

    // immutable variable (in bytecode)
    address public immutable verifiableProxyFactory;

    constructor(address _factory, bytes32 _salt) {
        verifiableProxyFactory = _factory;
        _setSalt(_salt);
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
    function initialize(address implementation, bytes memory data) public payable {
        require(implementation != address(0), "New implementation cannot be the zero address");
        require(_implementation() == address(0), "Already initialized");

        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    function getVerifiableProxySalt() public view returns (bytes32) {
        return _SALT_SLOT.erc7201Slot().getBytes32Slot().value;
    }

    function upgradeToAndCall(address implementation, bytes memory data) public payable {
        require(_implementation() != address(0), "Implementation not set");

        IProxyAuthorization currentImpl = IProxyAuthorization(address(this));
        IProxyAuthorization newImpl = IProxyAuthorization(implementation);

        require(currentImpl.isAuthorizedToUpgrade(msg.sender), "Not authorized to upgrade");
        require(newImpl.canUpgradeFrom(_implementation()), "Cannot upgrade from this implementation");

        ERC1967Utils.upgradeToAndCall(implementation, data);
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

    function _setSalt(bytes32 _salt) internal {
        _SALT_SLOT.erc7201Slot().getBytes32Slot().value = _salt;
    }

    function _delegate(address implementation) internal virtual override {
        bytes32 implementationSlot = ERC1967Utils.IMPLEMENTATION_SLOT;
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // check if implementation has changed
            let implAfter := sload(implementationSlot)

            if iszero(eq(implAfter, implementation)) {
                revert(0, 0)
            }

            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())

            switch result
            // delegatecall returns 0 on error.
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}
