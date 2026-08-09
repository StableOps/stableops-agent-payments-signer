import { describe, expect, it, vi } from 'vitest'

import { GrantReplayConflictError } from './errors'
import { RedisGrantAuthorizationStore, type RedisCommandClient } from './store'
import type { StoredGrantAuthorization } from './types'

describe('RedisGrantAuthorizationStore', () => {
  it('多个 Sidecar 实例并发处理同一 Grant 时只执行一次签名', async () => {
    const client = new FakeRedisClient()
    const left = createStore(client)
    const right = createStore(client)
    const create = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10))
      return authorization('hash_1')
    })

    const [first, second] = await Promise.all([
      left.getOrCreate('grant_1', 'hash_1', create),
      right.getOrCreate('grant_1', 'hash_1', create),
    ])

    expect(create).toHaveBeenCalledOnce()
    expect(first).toEqual(second)
  })

  it('相同 grantId 对应不同 Grant 内容时拒绝重放', async () => {
    const client = new FakeRedisClient()
    const store = createStore(client)
    await store.put(authorization('hash_1'))

    await expect(
      store.getOrCreate('grant_1', 'hash_2', async () => authorization('hash_2')),
    ).rejects.toBeInstanceOf(GrantReplayConflictError)
  })
})

function createStore(client: RedisCommandClient) {
  return new RedisGrantAuthorizationStore({
    client,
    pollIntervalMs: 1,
    waitTimeoutMs: 1_000,
  })
}

function authorization(grantTokenHash: string): StoredGrantAuthorization {
  return {
    grantId: 'grant_1',
    grantTokenHash,
    authorizationId: 'authorization_1',
    walletAddress: '0x1111111111111111111111111111111111111111',
    typedDataHash: `0x${'22'.repeat(32)}`,
    payload: {
      authorization: {
        from: '0x1111111111111111111111111111111111111111',
        to: '0x2222222222222222222222222222222222222222',
        value: '1',
        validAfter: '0',
        validBefore: '1',
        nonce: `0x${'33'.repeat(32)}`,
      },
      signature: `0x${'44'.repeat(65)}`,
    },
  }
}

class FakeRedisClient implements RedisCommandClient {
  private readonly values = new Map<string, string>()

  async sendCommand(command: readonly string[]): Promise<unknown> {
    if (command[0] === 'GET') return this.values.get(command[1]!) ?? null
    if (command[0] === 'SET' && command.includes('NX')) {
      const key = command[1]!
      if (this.values.has(key)) return null
      this.values.set(key, command[2]!)
      return 'OK'
    }
    if (command[0] === 'EVAL' && command[1]!.includes("redis.call('SET'")) {
      const key = command[3]!
      const existing = this.values.get(key)
      if (existing) return existing
      this.values.set(key, command[4]!)
      return ''
    }
    if (command[0] === 'EVAL') {
      const key = command[3]!
      if (this.values.get(key) === command[4]) {
        this.values.delete(key)
        return 1
      }
      return 0
    }
    throw new Error(`unsupported Redis command: ${command[0]}`)
  }
}
