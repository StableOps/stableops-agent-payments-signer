# StableOps Agent Payments Signer

[![npm version](https://img.shields.io/npm/v/@stableops/agent-payments-signer)](https://www.npmjs.com/package/@stableops/agent-payments-signer) [![npm downloads](https://img.shields.io/npm/dm/@stableops/agent-payments-signer)](https://www.npmjs.com/package/@stableops/agent-payments-signer) [![License](https://img.shields.io/npm/l/@stableops/agent-payments-signer)](https://www.npmjs.com/package/@stableops/agent-payments-signer) [![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org) [![Node](https://img.shields.io/badge/Node-%3E%3D20-339933)](https://nodejs.org)

[中文文档](./README.zh-CN.md)

StableOps Agent Signer is a customer-hosted signing sidecar for controlled x402
payments. It refuses arbitrary signing requests: every signature must match a
short-lived StableOps execution grant that binds the agent, wallet, network,
asset, recipient, amount, nonce, and validity window.

The private key stays in the customer's environment. The StableOps platform
stores only the verified public wallet address, signer type, and the relationship
that authorizes an agent to use that wallet.

## Features

- Compact JWS execution-grant verification with pinned Ed25519 public keys.
- Complete EIP-712 binding for EIP-3009 and Permit2 payments.
- EVM local private-key signer and Solana Ed25519 local signer.
- AWS KMS signer for `ECC_SECG_P256K1` asymmetric signing keys.
- Idempotent and replay-safe grant storage in memory or a local file.
- Loopback HTTP sidecar with optional constant-time bearer authentication.
- Request body limits and non-disclosing error responses.
- A CLI for validated one-shot wallet pairing and sidecar startup.
- Dual CJS and ESM builds with generated TypeScript declarations.

## Requirements

- Node.js 20 or newer.
- The StableOps execution-grant public key and key ID for the target environment.
- For local testing, a Base Sepolia wallet private key holding enough test USDC. The current EIP-3009 flow is submitted by the facilitator and does not require test ETH in the payer wallet.
- For AWS KMS, an `ECC_SECG_P256K1` key with `SIGN_VERIFY` usage and
  `ECDSA_SHA_256` support.

## Installation

Install globally for the CLI:

```bash
npm install -g @stableops/agent-payments-signer
```

Or add the package to an application that uses the library API:

```bash
pnpm add @stableops/agent-payments-signer
```

```bash
npm install @stableops/agent-payments-signer
```

```bash
yarn add @stableops/agent-payments-signer
```

## Quick Start

The dashboard generates a complete wallet-pairing command. It validates the challenge and checks
that the configured key controls the requested address before writing only the signature:

```bash
stableops-agent-payments-signer pair-wallet --signer local --challenge <base64url-challenge>
```

Start a Base Sepolia signer sidecar:

```bash
export STABLEOPS_EVM_PRIVATE_KEY_FILE='/protected/absolute/path/evm-private-key'
export STABLEOPS_GRANT_KEY_ID='replace-with-the-execution-grant-key-id'
export STABLEOPS_GRANT_PUBLIC_KEY_FILE='/protected/absolute/path/grant-public-key.pem'
export STABLEOPS_AUTHORIZATION_STORE_FILE='/protected/absolute/path/grant-authorizations.json'
export STABLEOPS_SIDECAR_TOKEN='replace-with-a-high-entropy-token'

stableops-agent-payments-signer serve --signer local
```

`pair-wallet` also accepts `--signer aws-kms` and `--signer solana`. Local keys are read only from
non-symlink files restricted to mode `0600`. Private-key values are never accepted in arguments or
environment variables. `serve` reads key paths,
network binding, grant verification, authorization storage, and sidecar authentication from
environment variables.

## Library API

Use `LocalTestSigner` only with Sandbox test assets:

```ts
import { readFileSync } from 'node:fs'
import {
  FileGrantAuthorizationStore,
  LocalTestSigner,
  startSignerSidecar,
} from '@stableops/agent-payments-signer'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`Missing environment variable ${name}`)
  return value
}

const signer = new LocalTestSigner({
  privateKey: readFileSync(
    required('STABLEOPS_EVM_PRIVATE_KEY_FILE'),
    'utf8',
  ).trim() as `0x${string}`,
  environment: 'SANDBOX',
  network: 'eip155:84532',
  grantVerification: {
    publicKeys: {
      [required('STABLEOPS_GRANT_KEY_ID')]: required('STABLEOPS_GRANT_PUBLIC_KEY'),
    },
  },
  store: new FileGrantAuthorizationStore('./data/grant-authorizations.json'),
})

const { url } = await startSignerSidecar({
  signer,
  host: '127.0.0.1',
  port: 8789,
  authToken: required('STABLEOPS_SIDECAR_TOKEN'),
})

console.log(`Signer listening at ${url}`)
```

Configure `@stableops/agent-payments-sdk` to call this loopback URL. The sidecar exposes
`GET /health` and authenticated `POST /v1/sign`; it rejects non-loopback listen
addresses.

For a managed key, create and validate an AWS KMS-backed signer:

```ts
import { AwsKmsSigner, FileGrantAuthorizationStore } from '@stableops/agent-payments-signer'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`Missing environment variable ${name}`)
  return value
}

const signer = await AwsKmsSigner.create({
  keyId: required('STABLEOPS_KMS_KEY_ID'),
  walletAddress: required('STABLEOPS_WALLET_ADDRESS') as `0x${string}`,
  environment: 'LIVE',
  network: 'eip155:8453',
  clientConfig: { region: process.env.AWS_REGION },
  grantVerification: {
    publicKeys: {
      [required('STABLEOPS_GRANT_KEY_ID')]: required('STABLEOPS_GRANT_PUBLIC_KEY'),
    },
  },
  store: new FileGrantAuthorizationStore('./data/grant-authorizations.json'),
})
```

At startup, `AwsKmsSigner.create()` retrieves the KMS public key and verifies that
its EVM address matches `walletAddress`. It signs only the validated EIP-712 digest
using `MessageType: DIGEST` and `ECDSA_SHA_256`.

Always set `environment` and `network` explicitly outside the Base Sepolia sandbox.
Use a separate signer instance, wallet, and authorization store for each network.

For multiple production Sidecar replicas, use `RedisGrantAuthorizationStore` instead of the
file store. It holds the full signing operation behind a Redis lease and atomically persists the
result, so concurrent replicas return the same authorization. Supply a small adapter exposing
`sendCommand(command: readonly string[])`; both node-redis and ioredis can be adapted without the
signer package owning the Redis connection lifecycle.
`AwsKmsSigner` supports EVM networks only; use `LocalSvmSigner` for Solana.

## Documentation

For wallet registration, key configuration, signer deployment, and the complete
Agent Payments flow, see the official documentation:

- English docs: https://stableops.dev/en/docs/agent-payments/signer
- Chinese docs: https://stableops.dev/zh/docs/agent-payments/signer
- Quickstart: https://stableops.dev/en/docs/agent-payments/quickstart

## Security and Current Support

Do not expose the sidecar directly to the public internet. Keep it on loopback,
use a high-entropy sidecar token, and
persist grant authorizations to preserve replay protection across restarts.

`LocalTestSigner` and `AwsKmsSigner` bind every grant to their configured EVM
environment and network. `LocalSvmSigner` handles Solana. Sandbox accepts test
networks only and Live accepts mainnets only; real-fund operation remains gated
by the StableOps organization risk controls.

## License

This SDK is licensed under `Apache-2.0`.
