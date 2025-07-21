# QCORP Key Generation Tool

A Node.js script for generating TOTP secrets and RSA signing keys based on various seed information.

## Installation

1. Install dependencies:
```bash
npm install
```

## Usage

### Generate TOTP Secret
```bash
node keygen.js totp user_id version(optional)
```

### Generate RSA Signing Keys

Note: If seed is not provided, a "randomized" timestamp will be used to generate the keys.

```bash
node keygen.js rsa seed(optional)
```

### Show Help
```bash
node keygen.js --help
```

## Output

### TOTP Secret
The script outputs a base32-encoded TOTP secret that can be used with authenticator apps.

### RSA Keys
The script outputs both private and public keys in PEM format:
- **Private Key**: Used for signing JWT tokens
- **Public Key**: Used for verifying JWT tokens

Timestamp and seed will also be returned for reference.

## Dependencies

- `crypto`: Node.js built-in crypto module
- `node-forge`: For RSA key generation
