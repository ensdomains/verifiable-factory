// SPDX-License-Identifier: MIT

// This contract was adapted from OpenZeppelin's ERC1967Proxy and UUPS proxy pattern.
// @ref: @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
// @ref: @openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol
pragma solidity ^0.8.20;

import {IProxyAuthorization} from "./IProxyAuthorization.sol";
import {IUUPSProxy} from "./IUUPSProxy.sol";

contract UUPSProxy is IUUPSProxy {
    /// @dev `keccak256(bytes("eth.ens.proxy.verifiable.salt"))`.
    bytes32 internal constant _SALT_SLOT = 0xb5b0a4d9ccf39d6e791e14c03248a14f4288ec2ddf7c269443c96ac5f0b17100; // "eth.ens.proxy.verifiable.salt"

    /// @dev `keccak256(bytes("eip1967.proxy.implementation")) - 1`.
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev `bytes4(keccak256(bytes("ImplementationCannotBeZeroAddress()")))`.
    uint256 internal constant _IMPLEMENTATION_CANNOT_BE_ZERO_ADDRESS_ERROR_SELECTOR = 0x0760838f;

    /// @dev `bytes4(keccak256(bytes("AlreadyInitialized()")))`.
    uint256 internal constant _ALREADY_INITIALIZED_ERROR_SELECTOR = 0x0dc149f0;

    /// @dev `bytes4(keccak256(bytes("UpgradeNotAllowedInContext()")))`.
    uint256 internal constant _UPGRADE_NOT_ALLOWED_IN_CONTEXT_ERROR_SELECTOR = 0x784cf700;

    /// @dev `bytes4(keccak256(bytes("ERC1967InvalidImplementation(address)")))`.
    uint256 internal constant _ERC1967_INVALID_IMPLEMENTATION_ERROR_SELECTOR = 0x4c9c8ce3;

    /// @dev `bytes4(keccak256(bytes("ERC1967NonPayable()")))`.
    uint256 internal constant _ERC1967_NON_PAYABLE_ERROR_SELECTOR = 0xb398979f;

    /// @dev `bytes4(keccak256(bytes("Upgraded(address)")))`.
    uint256 internal constant _UPGRADED_EVENT_SELECTOR =
        0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b;

    // immutable variable (in bytecode)
    address public immutable verifiableProxyFactory;

    bytes32 internal immutable _salt;

    constructor(address _factory, bytes32 salt_) {
        verifiableProxyFactory = _factory;
        _salt = salt_;
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
        assembly {
            if eq(implementation, 0) {
                mstore(0, _IMPLEMENTATION_CANNOT_BE_ZERO_ADDRESS_ERROR_SELECTOR)
                revert(0x1c, 0x04)
            }
            if iszero(eq(sload(_IMPLEMENTATION_SLOT), 0)) {
                mstore(0, _ALREADY_INITIALIZED_ERROR_SELECTOR)
                revert(0x1c, 0x04)
            }
            if iszero(extcodesize(implementation)) {
                mstore(0, _ERC1967_INVALID_IMPLEMENTATION_ERROR_SELECTOR)
                mstore(0x20, implementation)
                revert(0x1c, 0x24)
            }
            sstore(_IMPLEMENTATION_SLOT, implementation)
            log2(0, 0, _UPGRADED_EVENT_SELECTOR, implementation)

            let dlength := mload(data)
            switch dlength
            case 0 {
                if gt(0, callvalue()) {
                    mstore(0, _ERC1967_NON_PAYABLE_ERROR_SELECTOR)
                    revert(0x1c, 0x04)
                }
            }
            default {
                let result := delegatecall(gas(), implementation, add(data, 0x20), dlength, 0, 0)
                if iszero(result) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }
        }
    }

    function getVerifiableProxyData() public view returns (bytes32 salt, address implementation) {
        return (_salt, _implementation());
    }

    function upgradeToAndCall(address newImplementation, bytes memory /*data*/) public payable {
        if (newImplementation == address(0)) revert ImplementationCannotBeZeroAddress();
        if (_implementation() == address(0)) revert ImplementationNotSet();

        IProxyAuthorization newImpl = IProxyAuthorization(newImplementation);

        if (!newImpl.canUpgradeFrom(_implementation()))
            revert InvalidUpgradeTarget(_implementation(), newImplementation);

        // forward the call to the implementation
        _delegate(_implementation(), false);
    }

    /**
     * @dev Returns the current implementation address.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by ERC-1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function _implementation() internal view returns (address impl) {
        assembly {
            impl := sload(_IMPLEMENTATION_SLOT)
        }
    }

    function _delegate(address implementation, bool checkImplementation) internal {
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // check if implementation has changed
            let implAfter := sload(_IMPLEMENTATION_SLOT)

            if and(checkImplementation, iszero(eq(implAfter, implementation))) {
                mstore(0, _UPGRADE_NOT_ALLOWED_IN_CONTEXT_ERROR_SELECTOR)
                revert(0x1c, 0x04)
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

    fallback() external payable {
        _delegate(_implementation(), true);
    }

    receive() external payable {}
}
