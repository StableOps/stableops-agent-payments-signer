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

  it('签名超过初始租期时持续续租，避免另一个副本重复签名', async () => {
    vi.useFakeTimers()
    const client = new FakeRedisClient()
    const left = createStore(client, { lockTtlMs: 18 })
    const right = createStore(client, { lockTtlMs: 18 })
    const create = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 60))
      return authorization('hash_1')
    })

    try {
      const first = left.getOrCreate('grant_1', 'hash_1', create)
      await vi.advanceTimersByTimeAsync(25)
      const second = right.getOrCreate('grant_1', 'hash_1', create)
      await vi.advanceTimersByTimeAsync(100)

      await expect(Promise.all([first, second])).resolves.toEqual([
        authorization('hash_1'),
        authorization('hash_1'),
      ])
      expect(create).toHaveBeenCalledOnce()
      expect(client.renewals).toBeGreaterThan(0)
    } finally {
      vi.useRealTimers()
    }
  })

  it('租约丢失导致重复签名时两个副本都采用 Redis 中的规范结果', async () => {
    vi.useFakeTimers()
    const client = new FakeRedisClient(false)
    const left = createStore(client, { lockTtlMs: 15 })
    const right = createStore(client, { lockTtlMs: 15 })
    const leftCreate = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 45))
      return authorization('hash_1', '44')
    })
    const rightCreate = vi.fn(async () => authorization('hash_1', '55'))

    try {
      const first = left.getOrCreate('grant_1', 'hash_1', leftCreate)
      await vi.advanceTimersByTimeAsync(25)
      const second = right.getOrCreate('grant_1', 'hash_1', rightCreate)
      await vi.advanceTimersByTimeAsync(100)
      const [firstResult, secondResult] = await Promise.all([first, second])

      expect(leftCreate).toHaveBeenCalledOnce()
      expect(rightCreate).toHaveBeenCalledOnce()
      expect(firstResult).toEqual(secondResult)
      expect(firstResult).toEqual(authorization('hash_1', '55'))
    } finally {
      vi.useRealTimers()
    }
  })
})

function createStore(
  client: RedisCommandClient,
  options: Partial<ConstructorParameters<typeof RedisGrantAuthorizationStore>[0]> = {},
) {
  return new RedisGrantAuthorizationStore({
    client,
    pollIntervalMs: 1,
    waitTimeoutMs: 1_000,
    ...options,
  })
}

function authorization(grantTokenHash: string, signatureByte = '44'): StoredGrantAuthorization {
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
      signature: `0x${signatureByte.repeat(65)}`,
    },
  }
}

class FakeRedisClient implements RedisCommandClient {
  private readonly values = new Map<string, { value: string; expiresAt?: number }>()
  renewals = 0

  constructor(private readonly allowRenewal = true) {}

  async sendCommand(command: readonly string[]): Promise<unknown> {
    if (command[0] === 'GET') return this.get(command[1]!)
    if (command[0] === 'SET' && command.includes('NX')) {
      const key = command[1]!
      if (this.get(key)) return null
      this.values.set(key, {
        value: command[2]!,
        expiresAt: Date.now() + Number(command[command.indexOf('PX') + 1]),
      })
      return 'OK'
    }
    if (command[0] === 'EVAL' && command[1]!.includes("redis.call('SET'")) {
      const key = command[3]!
      const existing = this.get(key)
      if (existing) return existing
      this.values.set(key, {
        value: command[4]!,
        expiresAt: Date.now() + Number(command[5]),
      })
      return ''
    }
    if (command[0] === 'EVAL' && command[1]!.includes("redis.call('PEXPIRE'")) {
      const key = command[3]!
      if (!this.allowRenewal || this.get(key) !== command[4]) return 0
      this.values.set(key, {
        value: command[4]!,
        expiresAt: Date.now() + Number(command[5]),
      })
      this.renewals += 1
      return 1
    }
    if (command[0] === 'EVAL') {
      const key = command[3]!
      if (this.get(key) === command[4]) {
        this.values.delete(key)
        return 1
      }
      return 0
    }
    throw new Error(`unsupported Redis command: ${command[0]}`)
  }

  private get(key: string): string | null {
    const stored = this.values.get(key)
    if (!stored) return null
    if (stored.expiresAt !== undefined && stored.expiresAt <= Date.now()) {
      this.values.delete(key)
      return null
    }
    return stored.value
  }
}
