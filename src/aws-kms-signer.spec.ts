import { GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms'
import { x402ExactPermit2ProxyAddress } from '@x402/evm'
import { generateKeyPairSync } from 'node:crypto'
import { bytesToHex, hexToBytes } from 'viem'
import { privateKeyToAccount, sign } from 'viem/accounts'
import { describe, expect, it, vi } from 'vitest'

import {
  AwsKmsSigner,
  decodeKmsDerSignature,
  normalizeLowS,
  type KmsSigningClient,
} from './aws-kms-signer'
import { GrantBindingError } from './errors'
import { signExecutionGrant } from './grant'
import { MemoryGrantAuthorizationStore } from './store'
import { hashGrantTypedData } from './typed-data'
import type { ExecutionGrantClaims } from './types'

const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const
const TEST_NOW = 1_700_000_000

describe('AwsKmsSigner', () => {
  it('校验 KMS 公钥、解码 DER 并生成可恢复且幂等的低 s 签名', async () => {
    const account = privateKeyToAccount(TEST_PRIVATE_KEY)
    const fixture = createGrantFixture()
    const send = vi.fn(async (command: GetPublicKeyCommand | SignCommand) => {
      if (command instanceof GetPublicKeyCommand) {
        return {
          KeySpec: 'ECC_SECG_P256K1',
          KeyUsage: 'SIGN_VERIFY',
          SigningAlgorithms: ['ECDSA_SHA_256'],
          PublicKey: subjectPublicKeyInfo(account.publicKey),
        }
      }
      const signature = await sign({
        hash: bytesToHex(command.input.Message!),
        privateKey: TEST_PRIVATE_KEY,
      })
      return {
        KeyId: 'kms-key-1',
        SigningAlgorithm: 'ECDSA_SHA_256',
        Signature: derSignature(signature.r, signature.s),
      }
    })
    const signer = await AwsKmsSigner.create({
      keyId: 'kms-key-1',
      walletAddress: account.address,
      client: { send } as unknown as KmsSigningClient,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const token = fixture.sign(createClaims({ walletAddress: account.address }))

    const [first, replay] = await Promise.all([signer.sign(token), signer.sign(token)])

    expect(first).toEqual(replay)
    expect(first.signature).toMatch(/^0x[0-9a-f]{130}$/u)
    expect(send).toHaveBeenCalledTimes(2)
    const signCommand = send.mock.calls[1]?.[0]
    expect(signCommand).toBeInstanceOf(SignCommand)
    expect((signCommand as SignCommand).input).toMatchObject({
      KeyId: 'kms-key-1',
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    })
  })

  it('KMS 公钥与登记钱包不一致时启动失败', async () => {
    const account = privateKeyToAccount(TEST_PRIVATE_KEY)
    const other = privateKeyToAccount(
      '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    )
    const client = {
      send: vi.fn(async () => ({
        KeySpec: 'ECC_SECG_P256K1',
        KeyUsage: 'SIGN_VERIFY',
        SigningAlgorithms: ['ECDSA_SHA_256'],
        PublicKey: subjectPublicKeyInfo(account.publicKey),
      })),
    } as unknown as KmsSigningClient

    await expect(
      AwsKmsSigner.create({
        keyId: 'kms-key-1',
        walletAddress: other.address,
        client,
        grantVerification: { publicKeys: {} },
        store: new MemoryGrantAuthorizationStore(),
      }),
    ).rejects.toBeInstanceOf(GrantBindingError)
  })

  it('Permit2 付款载荷使用 x402 库导出的代理地址', async () => {
    const account = privateKeyToAccount(TEST_PRIVATE_KEY)
    const fixture = createGrantFixture()
    const client = {
      send: vi.fn(async (command: GetPublicKeyCommand | SignCommand) => {
        if (command instanceof GetPublicKeyCommand) {
          return {
            KeySpec: 'ECC_SECG_P256K1',
            KeyUsage: 'SIGN_VERIFY',
            SigningAlgorithms: ['ECDSA_SHA_256'],
            PublicKey: subjectPublicKeyInfo(account.publicKey),
          }
        }
        const signature = await sign({
          hash: bytesToHex(command.input.Message!),
          privateKey: TEST_PRIVATE_KEY,
        })
        return {
          KeyId: 'kms-key-1',
          SigningAlgorithm: 'ECDSA_SHA_256',
          Signature: derSignature(signature.r, signature.s),
        }
      }),
    } as unknown as KmsSigningClient
    const signer = await AwsKmsSigner.create({
      keyId: 'kms-key-1',
      walletAddress: account.address,
      network: 'eip155:97',
      client,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const token = fixture.sign(
      createClaims({
        walletAddress: account.address,
        network: 'eip155:97',
        transferMethod: 'permit2',
        assetContract: '0x64544969ed7EBf5f083679233325356EbE738930',
        amountAtomic: '1000000000000000000',
      }),
    )

    const result = await signer.sign(token)

    expect(result.payload).toMatchObject({
      permit2Authorization: {
        spender: x402ExactPermit2ProxyAddress,
      },
    })
  })

  it('拒绝非规范 DER，并把高 s 规范化为低 s', () => {
    expect(() => decodeKmsDerSignature(Uint8Array.from([0x30, 0x01, 0x00]))).toThrow(
      GrantBindingError,
    )
    const order =
      0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
    expect(normalizeLowS(order - 1n)).toBe(1n)
  })
})

function createGrantFixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const keyId = 'grant-test-1'
  return {
    keyId,
    publicKey,
    sign: (claims: ExecutionGrantClaims) =>
      signExecutionGrant(claims, {
        keyId,
        privateKey,
      }),
  }
}

function createClaims(overrides: Partial<ExecutionGrantClaims> = {}): ExecutionGrantClaims {
  const claims = {
    issuer: 'stableops',
    audience: 'stableops-agent-signer',
    grantId: 'grant_1',
    organizationId: 'org_1',
    environment: 'SANDBOX',
    agentId: 'pagt_1',
    intentId: 'pint_1',
    authorizationId: 'paut_1',
    walletId: 'paw_1',
    walletAddress: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    x402Version: 2,
    scheme: 'exact',
    network: 'eip155:84532',
    assetContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    tokenName: 'USDC',
    tokenVersion: '2',
    payTo: '0x0000000000000000000000000000000000000001',
    amountAtomic: '20000',
    validAfter: '0',
    validBefore: '1700000300',
    nonce: `0x${'22'.repeat(32)}`,
    typedDataHash: `0x${'00'.repeat(32)}`,
    issuedAt: TEST_NOW,
    expiresAt: TEST_NOW + 120,
    ...overrides,
  } as ExecutionGrantClaims
  if (!overrides.typedDataHash) claims.typedDataHash = hashGrantTypedData(claims)
  return claims
}

function subjectPublicKeyInfo(publicKey: `0x${string}`): Uint8Array {
  return Uint8Array.from(
    Buffer.concat([
      Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex'),
      Buffer.from(publicKey.slice(2), 'hex'),
    ]),
  )
}

function derSignature(r: `0x${string}`, s: `0x${string}`): Uint8Array {
  const rInteger = derInteger(hexToBytes(r))
  const sInteger = derInteger(hexToBytes(s))
  return Uint8Array.from([0x30, rInteger.length + sInteger.length, ...rInteger, ...sInteger])
}

function derInteger(input: Uint8Array): number[] {
  const bytes = [...input]
  while (bytes.length > 1 && bytes[0] === 0) bytes.shift()
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0)
  return [0x02, bytes.length, ...bytes]
}
