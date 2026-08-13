import { generateKeyPairSync } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { GrantBindingError, GrantReplayConflictError, InvalidGrantError } from './errors'
import { signExecutionGrant, verifyExecutionGrant } from './grant'
import { LocalTestSigner } from './local-signer'
import { MemoryGrantAuthorizationStore } from './store'
import { hashGrantTypedData } from './typed-data'
import type { ExecutionGrantClaims } from './types'

const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const
const TEST_NOW = 1_700_000_000

describe('LocalTestSigner', () => {
  it('验证 Grant、签署 EIP-3009，并对相同 Grant 幂等返回', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const token = fixture.sign(createClaims({ walletAddress: signer.address }))

    const [first, second] = await Promise.all([signer.sign(token), signer.sign(token)])

    expect(first).toEqual(second)
    expect(first.authorization?.from).toBe(signer.address)
    expect(first.authorization?.to).toBe(getBaseClaims().payTo)
    expect(first.signature).toMatch(/^0x[0-9a-f]{130}$/u)
  })

  it('拒绝被修改的 typed data hash', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const claims = createClaims({
      walletAddress: signer.address,
      typedDataHash: `0x${'11'.repeat(32)}`,
    })

    await expect(signer.sign(fixture.sign(claims))).rejects.toBeInstanceOf(GrantBindingError)
  })

  it('在 BNB Smart Chain 测试网上生成 Permit2 付款载荷', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      network: 'eip155:97',
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const claims = createClaims({
      walletAddress: signer.address,
      network: 'eip155:97',
      transferMethod: 'permit2',
      assetContract: '0x64544969ed7EBf5f083679233325356EbE738930',
      amountAtomic: '1000000000000000000',
    })

    const result = await signer.sign(fixture.sign(claims))

    expect(result.payload).toHaveProperty('permit2Authorization')
    expect(result.payload).toMatchObject({
      permit2Authorization: {
        from: signer.address,
        permitted: { amount: '1000000000000000000' },
      },
    })
  })

  it('同一 grant ID 的不同声明返回冲突', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const original = createClaims({ walletAddress: signer.address })
    await signer.sign(fixture.sign(original))

    const changed = createClaims({
      walletAddress: signer.address,
      amountAtomic: '20001',
    })
    await expect(signer.sign(fixture.sign(changed))).rejects.toBeInstanceOf(
      GrantReplayConflictError,
    )
  })

  it('并发处理相同 grant ID 的不同声明时立即返回冲突', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const first = fixture.sign(createClaims({ walletAddress: signer.address }))
    const second = fixture.sign(
      createClaims({ walletAddress: signer.address, amountAtomic: '20001' }),
    )

    const results = await Promise.allSettled([signer.sign(first), signer.sign(second)])

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    const rejected = results.find((result) => result.status === 'rejected')
    expect(rejected).toMatchObject({ reason: expect.any(GrantReplayConflictError) })
  })

  it('调用方修改签名结果不会污染内存存储中的规范结果', async () => {
    const fixture = createFixture()
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => TEST_NOW,
      },
      store: new MemoryGrantAuthorizationStore(),
    })
    const token = fixture.sign(createClaims({ walletAddress: signer.address }))

    const first = await signer.sign(token)
    if (!('authorization' in first.payload)) throw new Error('缺少 EIP-3009 授权')
    first.payload.authorization.value = '999'
    if (first.authorization) first.authorization.value = '999'

    const second = await signer.sign(token)

    expect(second.authorization?.value).toBe('20000')
    expect('authorization' in second.payload && second.payload.authorization.value).toBe('20000')
  })

  it('拒绝过期 Grant', () => {
    const fixture = createFixture()
    const claims = createClaims({ expiresAt: 1_700_000_010 })
    const token = fixture.sign(claims)

    expect(() =>
      verifyExecutionGrant(token, {
        publicKeys: { [fixture.keyId]: fixture.publicKey },
        now: () => 1_700_000_100,
      }),
    ).toThrow(InvalidGrantError)
  })
})

function createFixture() {
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
    ...getBaseClaims(),
    ...overrides,
  } as ExecutionGrantClaims
  if (!overrides.typedDataHash) {
    claims.typedDataHash = hashGrantTypedData(claims)
  }
  return claims
}

function getBaseClaims(): ExecutionGrantClaims {
  return {
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
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_120,
  }
}
