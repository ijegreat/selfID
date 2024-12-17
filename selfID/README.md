# Decentralized Identity and Verifiable Credentials System

## Overview

This selfID Clarity smart contract provides a robust, secure, and privacy-preserving solution for decentralized identity management and credential verification in the Web 3 ecosystem. The system allows users to create and control their own digital identities, issue verifiable credentials, and manage them with full transparency and security.

## Key Features

- **User-Controlled Identities**
  - Create unique decentralized identities
  - Attach metadata to identities
  - Prevent multiple identities per user

- **Credential Management**
  - Issue credentials with flexible configurations
  - Optional expiration for credentials
  - Secure credential verification
  - Credential revocation capabilities

- **Security Mechanisms**
  - Access control for identity and credential operations
  - Error handling for various scenarios
  - Emergency contract pause functionality

## Prerequisites

- Stacks blockchain environment
- Clarity smart contract development tools
- Web 3 wallet supporting Stacks (e.g., Hiro Wallet)

## Contract Functions

### Identity Management
- `create-identity`: Establish a new decentralized identity
  - Parameters: DID, public key, metadata
- `update-identity-metadata`: Modify existing identity metadata

### Credential Operations
- `issue-credential`: Create a new verifiable credential
  - Parameters: Recipient, credential ID, type, data, expiration
- `verify-credential`: Check credential validity and non-expiration
- `revoke-credential`: Invalidate a previously issued credential

### Utility Functions
- `identity-exists`: Check if an identity is registered
- `toggle-contract-pause`: Emergency contract pause mechanism

## Usage Examples

### Creating an Identity
```clarity
(contract-call? .decentralized-identity create-identity 
  "did:stacks:user123" 
  0x01234... 
  "Professional Developer Profile"
)
```

### Issuing a Credential
```clarity
(contract-call? .decentralized-identity issue-credential
  recipient-address
  "cert-blockchain-developer"
  "professional-certification"
  "Certified Blockchain Developer"
  (some u1000000)  ;; Optional expiration block height
)
```

## Error Handling

The contract defines several error constants:
- `ERR-NOT-AUTHORIZED`: Unauthorized access attempt
- `ERR-IDENTITY-EXISTS`: Duplicate identity creation
- `ERR-IDENTITY-NOT-FOUND`: Identity lookup failure
- `ERR-CREDENTIAL-EXISTS`: Duplicate credential creation
- `ERR-CREDENTIAL-NOT-FOUND`: Credential lookup failure
- `ERR-INVALID-CREDENTIAL`: Credential validation failure

## Security Considerations

- Only identity owners can modify their metadata
- Credential issuance and revocation restricted to authorized parties
- Built-in emergency pause mechanism
- No storage of sensitive personal information

## Deployment

1. Compile the Clarity contract
2. Deploy to Stacks blockchain
3. Interact via Web 3 wallet or developer tools

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request
