import { generateKeyPairSync } from 'node:crypto'

import { afterEach, describe, expect, it } from 'vitest'

import { signExecutionGrant } from './grant'
import { LocalTestSigner } from './local-signer'
import { startSignerSidecar } from './sidecar'
import { MemoryGrantAuthorizationStore } from './store'
import { hashGrantTypedData } from './typed-data'
import type { ExecutionGrantClaims } from './types'

const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const

describe('signer sidecar', () => {
  const servers: Array<ReturnType<typeof startSignerSidecar> extends Promise<infer T> ? T : never> =
    []

  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        ({ server }) =>
          new Promise<void>((resolve, reject) => {
            server.close((error) => (error ? reject(error) : resolve()))
          }),
      ),
    )
  })

  it('只在认证通过后签名', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const signer = new LocalTestSigner({
      privateKey: TEST_PRIVATE_KEY,
      grantVerification: { publicKeys: { key_1: publicKey } },
      store: new MemoryGrantAuthorizationStore(),
    })
    const sidecar = await startSignerSidecar({ signer, authToken: 'sidecar-secret' })
    servers.push(sidecar)
    const claims = createClaims(signer.address)
    const grant = signExecutionGrant(claims, { keyId: 'key_1', privateKey })

    const denied = await fetch(`${sidecar.url}/v1/sign`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ grant }),
    })
    expect(denied.status).toBe(401)

    const accepted = await fetch(`${sidecar.url}/v1/sign`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer sidecar-secret',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ grant }),
    })
    expect(accepted.status).toBe(200)
    await expect(accepted.json()).resolves.toMatchObject({
      grantId: claims.grantId,
      authorizationId: claims.authorizationId,
      walletAddress: signer.address,
    })
  })
})

function createClaims(walletAddress: `0x${string}`): ExecutionGrantClaims {
  const now = Math.floor(Date.now() / 1000)
  const claims: ExecutionGrantClaims = {
    issuer: 'stableops',
    audience: 'stableops-agent-signer',
    grantId: 'grant_sidecar',
    organizationId: 'org_1',
    environment: 'SANDBOX',
    agentId: 'pagt_1',
    intentId: 'pint_1',
    authorizationId: 'paut_1',
    walletId: 'paw_1',
    walletAddress,
    x402Version: 2,
    scheme: 'exact',
    network: 'eip155:84532',
    assetContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    tokenName: 'USDC',
    tokenVersion: '2',
    payTo: '0x0000000000000000000000000000000000000001',
    amountAtomic: '20000',
    validAfter: '0',
    validBefore: String(now + 300),
    nonce: `0x${'33'.repeat(32)}`,
    typedDataHash: `0x${'00'.repeat(32)}`,
    issuedAt: now,
    expiresAt: now + 120,
  }
  claims.typedDataHash = hashGrantTypedData(claims)
  return claims
}
