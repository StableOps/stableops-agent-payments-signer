import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { loadGrantVerificationKeys } from './grant-key-discovery'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  )
})

describe('execution grant verification key discovery', () => {
  it('默认从 StableOps API 自动获取 JWKS', async () => {
    const jwk = publicJwk()
    const fetchImpl = vi.fn(async () =>
      Response.json({
        keys: [{ ...jwk, kid: 'grant-key-1', use: 'sig', alg: 'EdDSA' }],
      }),
    ) as typeof fetch

    const result = await loadGrantVerificationKeys({}, fetchImpl)

    expect(fetchImpl).toHaveBeenCalledWith(
      'https://api.stableops.dev/v1/public/agent-payments/execution-grant-keys',
      expect.objectContaining({ headers: { accept: 'application/json' } }),
    )
    expect(Object.keys(result)).toEqual(['grant-key-1'])
  })

  it('自部署时使用 STABLEOPS_API_URL 获取 JWKS', async () => {
    const jwk = publicJwk()
    const fetchImpl = vi.fn(async () =>
      Response.json({
        keys: [{ ...jwk, kid: 'self-hosted-1', use: 'sig', alg: 'EdDSA' }],
      }),
    ) as typeof fetch

    await loadGrantVerificationKeys({ STABLEOPS_API_URL: 'http://127.0.0.1:3001/' }, fetchImpl)

    expect(fetchImpl).toHaveBeenCalledWith(
      'http://127.0.0.1:3001/v1/public/agent-payments/execution-grant-keys',
      expect.any(Object),
    )
  })

  it('显式配置本地 PEM 时不访问网络', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'stableops-grant-key-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'grant-public.pem')
    const { publicKey } = generateKeyPairSync('ed25519')
    const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    await writeFile(filePath, pem)
    const fetchImpl = vi.fn() as unknown as typeof fetch

    const result = await loadGrantVerificationKeys(
      {
        STABLEOPS_GRANT_KEY_ID: 'pinned-key-1',
        STABLEOPS_GRANT_PUBLIC_KEY_FILE: filePath,
      },
      fetchImpl,
    )

    expect(result).toEqual({ 'pinned-key-1': pem })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('拒绝通过远程明文 HTTP 获取密钥', async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch

    await expect(
      loadGrantVerificationKeys({ STABLEOPS_API_URL: 'http://api.example.com' }, fetchImpl),
    ).rejects.toThrow('STABLEOPS_API_URL must use HTTPS')
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('拒绝无效的密钥发现响应', async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        keys: [
          {
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'invalid',
            kid: 'grant-key-1',
            use: 'sig',
            alg: 'EdDSA',
          },
        ],
      }),
    ) as typeof fetch

    await expect(loadGrantVerificationKeys({}, fetchImpl)).rejects.toThrow(
      'returned an invalid Ed25519 key',
    )
  })
})

function publicJwk() {
  const { publicKey } = generateKeyPairSync('ed25519')
  return publicKey.export({ format: 'jwk' })
}
