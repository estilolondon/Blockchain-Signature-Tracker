# Digital Document Authentication & Multi-Signature Verification System

A comprehensive blockchain-based smart contract for secure document authentication, cryptographic signature verification, and multi-party authorization tracking on the Stacks blockchain.

## Overview

This Clarity smart contract enables tamper-proof document registration, lifecycle management, and legally-binding digital signature workflows for enterprise and legal use cases. It provides a decentralized solution for document authentication with cryptographic verification capabilities.

## Features

- **Document Registration**: Register documents with metadata and hash-based identification
- **Multi-Signature Support**: Enable multiple parties to digitally sign documents
- **Cryptographic Verification**: Verify signatures using secp256k1 public key cryptography
- **Access Control**: Creator-based authorization for document management
- **Lifecycle Management**: Track document status (active/revoked)
- **Batch Processing**: Verify multiple signatures simultaneously
- **Public Key Registry**: Manage cryptographic keys for signers

## Core Components

### Data Structures

1. **Document Registry** (`authenticated-documents`)
   - Stores document metadata, creator information, and signature counts
   - Tracks document status and creation timestamps

2. **Signature Records** (`signature-verification-records`)
   - Individual signature verification records
   - Links documents to signers with cryptographic proofs

3. **Public Key Registry** (`registered-public-keys`)
   - Stores compressed secp256k1 public keys for signature verification
   - Maps principals to their cryptographic keys

## Installation & Deployment

### Prerequisites

- Stacks blockchain node or access to a Stacks testnet/mainnet
- Clarity CLI tools
- Understanding of Clarity smart contract development

### Deployment Steps

1. **Clone or download the contract code**
2. **Deploy to Stacks blockchain**:
   ```bash
   clarity-cli deploy document-auth-contract.clar --network testnet
   ```

## Usage Guide

### 1. Register Public Key

Before signing documents, users must register their public key:

```clarity
(contract-call? .document-auth register-signing-key 0x02a1b2c3d4e5f6...)
```

### 2. Authenticate New Document

Register a document for authentication:

```clarity
(contract-call? .document-auth authenticate-new-document 
  0x123456789abcdef... ;; document hash
  u"Contract Agreement" ;; document name
  u"Legal contract between parties A and B") ;; summary
```

### 3. Sign Document

Process a digital signature for a document:

```clarity
(contract-call? .document-auth process-document-signature
  0x123456789abcdef... ;; document hash
  0x304502210... ;; digital signature
  u"Approved and signed by Party A") ;; signature context
```

### 4. Verify Signatures

Check if multiple parties have signed a document:

```clarity
(contract-call? .document-auth verify-batch-signatures
  0x123456789abcdef... ;; document hash
  (list 'SP1ABC... 'SP2DEF... 'SP3GHI...)) ;; signer principals
```

## API Reference

### Read-Only Functions

#### Document Queries
- `fetch-document-record(document-hash)` - Get complete document record
- `is-document-authenticated(document-hash)` - Check if document exists
- `count-document-signatures(document-hash)` - Get signature count
- `get-total-authenticated-documents()` - Get total system documents

#### Signature Verification
- `fetch-signature-record(document-hash, signer-principal)` - Get signature details
- `has-principal-signed(document-hash, signer-principal)` - Check if principal signed
- `verify-signature-authenticity(message-hash, signature, public-key)` - Verify signature

#### Key Management
- `fetch-principal-public-key(principal-owner)` - Get registered public key
- `is-valid-secp256k1-format(public-key)` - Validate key format

### Public Functions

#### Key Management
- `register-signing-key(compressed-secp256k1-key)` - Register public key

#### Document Management
- `authenticate-new-document(document-hash, name, summary)` - Register new document
- `modify-document-metadata(document-hash, updated-name, updated-summary)` - Update document info
- `revoke-document-access(document-hash)` - Revoke document access

#### Signature Processing
- `process-document-signature(document-hash, signature, context)` - Add signature to document
- `invalidate-signature(document-hash, target-signer)` - Invalidate a signature
- `verify-batch-signatures(document-hash, signer-list)` - Verify multiple signatures

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Invalid parameter input or malformed data |
| 401 | Unauthorized operation |
| 403 | Document access revoked |
| 404 | Document or public key not found |
| 409 | Document already registered or duplicate signature |

## Security Considerations

### Cryptographic Security
- Uses secp256k1 elliptic curve cryptography
- Requires proper key management and secure signature generation
- Validates signature authenticity against registered public keys

### Access Control
- Document creators have exclusive rights to modify metadata and revoke access
- Only registered key holders can provide valid signatures
- Prevents duplicate signatures from the same principal

### Best Practices
1. **Key Security**: Store private keys securely and never expose them
2. **Hash Verification**: Always verify document hashes before signing
3. **Context Documentation**: Provide clear signature contexts for audit trails
4. **Regular Audits**: Monitor signature validity and document status

## Limitations

- Maximum 10 signers per batch verification
- Document names limited to 256 UTF-8 characters
- Document summaries limited to 1024 UTF-8 characters
- Signature contexts limited to 256 UTF-8 characters
- No built-in document storage (only hashes are stored)

## Use Cases

### Legal Documents
- Contract signing and verification
- Legal agreement authentication
- Multi-party consent tracking

### Enterprise Applications
- Document approval workflows
- Compliance documentation
- Audit trail maintenance

### Government Services
- Official document verification
- Citizen service authentication
- Regulatory compliance tracking