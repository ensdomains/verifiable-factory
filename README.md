# Verifiable Factory Contract

A system for deploying and verifying proxy contracts with predictable storage layouts and deterministic addresses using CREATE2.

## Components

### 1. Verifiable Factory Contract
- Deploys TransparentVerifiableProxy instances using CREATE2 opcode
- Handles on-chain verification of deployed proxies
- Manages proxy upgrades through a secure ownership model
- Uses deterministic salt generation for predictable addresses

### 2. TransparentVerifiableProxy
- Transparent proxy pattern with verified storage layout
- Fixed storage slots via [SlotDerivation](https://docs.openzeppelin.com/contracts/5.x/api/utils#SlotDerivation) under `proxy.verifiable` namespace
  - `salt` (uint256)
  - `owner` (address)
- Immutable `creator` field (set in bytecode)
- Implements secure upgrade mechanism
- Initializable to prevent implementation tampering

## Architecture

```mermaid
sequenceDiagram
    participant User
    participant VerifiableFactory
    participant TransparentVerifiableProxy
    participant Implementation

    %% Deployment Flow
    User->>VerifiableFactory: deployProxy(implementation, salt)
    VerifiableFactory->>VerifiableFactory: Generate outerSalt (keccak256(sender, salt))
    VerifiableFactory->>TransparentVerifiableProxy: CREATE2 deployment
    TransparentVerifiableProxy->>TransparentVerifiableProxy: Set immutable creator
    VerifiableFactory->>TransparentVerifiableProxy: initialize(salt, owner, implementation)
    TransparentVerifiableProxy->>Implementation: Delegate calls
    VerifiableFactory->>User: Return proxy address

    %% Verification Flow
    User->>VerifiableFactory: verifyContract(proxyAddress)
    VerifiableFactory->>TransparentVerifiableProxy: Check contract existence
    VerifiableFactory->>TransparentVerifiableProxy: Query salt and creator
    VerifiableFactory->>VerifiableFactory: Reconstruct CREATE2 address
    VerifiableFactory->>User: Return verification result

    %% Upgrade Flow
    User->>VerifiableFactory: upgradeImplementation(proxy, newImpl, data)
    VerifiableFactory->>TransparentVerifiableProxy: Check caller is owner
    VerifiableFactory->>TransparentVerifiableProxy: upgradeToAndCall(newImpl, data)
    TransparentVerifiableProxy->>Implementation: Switch delegation target
```
