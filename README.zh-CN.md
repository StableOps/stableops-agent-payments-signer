# StableOps Agent Signer

[![npm version](https://img.shields.io/npm/v/@stableops/agent-signer)](https://www.npmjs.com/package/@stableops/agent-signer) [![npm downloads](https://img.shields.io/npm/dm/@stableops/agent-signer)](https://www.npmjs.com/package/@stableops/agent-signer) [![License](https://img.shields.io/npm/l/@stableops/agent-signer)](https://www.npmjs.com/package/@stableops/agent-signer) [![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org) [![Node](https://img.shields.io/badge/Node-%3E%3D20-339933)](https://nodejs.org)

[查看英文说明](./README.md)

StableOps Agent Signer 是由客户自行托管的签名器伴随服务，用于执行受控的 x402 付款。它拒绝任意签名请求：每个签名都必须匹配 StableOps 签发的短时执行授权，其中绑定代理、钱包、网络、资产、收款地址、金额、随机数和有效期。

私钥始终留在客户环境中。StableOps 平台只保存已验证的公开钱包地址、签名器类型，以及允许指定代理使用该钱包的授权关系。

## 功能

- 使用固定的 Ed25519 公钥验证紧凑 JWS 执行授权。
- 完整绑定 EIP-3009 和 Permit2 付款的 EIP-712 字段。
- 提供 EVM 本地私钥签名器和 Solana Ed25519 本地签名器。
- 支持使用 `ECC_SECG_P256K1` 非对称签名密钥的 AWS KMS 签名器。
- 通过内存或本地文件提供幂等且防重放的执行授权存储。
- 提供仅监听环回地址的 HTTP 伴随服务，可选用常量时间 Bearer 认证。
- 限制请求体大小，并避免错误响应泄露内部信息。
- 同时输出 CJS、ESM 和 TypeScript 类型声明。

## 环境要求

- Node.js 20 或更高版本。
- 目标环境对应的 StableOps 执行授权公钥和密钥编号。
- 本地测试需要 Base Sepolia 钱包私钥，钱包内应有足够的测试 USDC。当前 EIP-3009 流程由结算服务提交交易，付款钱包不需要测试 ETH。
- AWS KMS 需要用途为 `SIGN_VERIFY` 且支持 `ECDSA_SHA_256` 的 `ECC_SECG_P256K1` 密钥。

## 安装

```bash
pnpm add @stableops/agent-signer
```

```bash
npm install @stableops/agent-signer
```

```bash
yarn add @stableops/agent-signer
```

## 快速开始

`LocalTestSigner` 只能用于沙盒测试资产：

```ts
import {
  FileGrantAuthorizationStore,
  LocalTestSigner,
  startSignerSidecar,
} from '@stableops/agent-signer'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`缺少环境变量 ${name}`)
  return value
}

const signer = new LocalTestSigner({
  privateKey: required('BASE_SEPOLIA_TEST_PRIVATE_KEY') as `0x${string}`,
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

console.log(`签名器正在监听 ${url}`)
```

将 `@stableops/agent-sdk` 配置为调用这个环回地址。伴随服务提供 `GET /health` 和需要认证的 `POST /v1/sign`，并拒绝监听非环回地址。

如需使用托管密钥，可以创建并验证由 AWS KMS 支持的签名器：

```ts
import { AwsKmsSigner, FileGrantAuthorizationStore } from '@stableops/agent-signer'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`缺少环境变量 ${name}`)
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

启动时，`AwsKmsSigner.create()` 会获取 KMS 公钥，并验证其 EVM 地址与 `walletAddress` 一致。它只会使用 `MessageType: DIGEST` 和 `ECDSA_SHA_256` 签署通过验证的 EIP-712 摘要。

除 Base Sepolia 沙盒外，必须显式设置 `environment` 和 `network`。每个网络使用独立的签名器实例、钱包和授权记录存储。`AwsKmsSigner` 仅支持 EVM 网络；Solana 使用 `LocalSvmSigner`。

## 官方文档

钱包注册、密钥配置、签名器部署和完整的 Agent Payments 流程，请查看官方文档：

- 中文文档：https://stableops.dev/zh/docs/agent-payments/signer
- 英文文档：https://stableops.dev/en/docs/agent-payments/signer
- 快速开始：https://stableops.dev/zh/docs/agent-payments/quickstart

## 安全和当前支持范围

不要把伴随服务直接暴露到公网。应使其仅监听环回地址，使用高熵伴随服务令牌，并持久化执行授权记录，以便在进程重启后继续防止重放。

`LocalTestSigner` 和 `AwsKmsSigner` 会把每份执行授权绑定到配置的 EVM 环境和网络，`LocalSvmSigner` 用于 Solana。沙盒只能使用测试网，正式环境只能使用主网；真实资金操作仍受 StableOps 组织风控门禁约束。

## 许可证

本 SDK 使用 `Apache-2.0` 许可证。
