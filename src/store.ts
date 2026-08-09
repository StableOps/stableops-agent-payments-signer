import { randomUUID } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

import type { GrantAuthorizationStore, StoredGrantAuthorization } from './types'
import { AgentSignerError, GrantReplayConflictError } from './errors'

export class MemoryGrantAuthorizationStore implements GrantAuthorizationStore {
  private readonly values = new Map<string, StoredGrantAuthorization>()

  async get(grantId: string): Promise<StoredGrantAuthorization | null> {
    return this.values.get(grantId) ?? null
  }

  async put(value: StoredGrantAuthorization): Promise<void> {
    this.values.set(value.grantId, value)
  }
}

export class FileGrantAuthorizationStore implements GrantAuthorizationStore {
  private queue = Promise.resolve()

  constructor(private readonly filePath: string) {}

  async get(grantId: string): Promise<StoredGrantAuthorization | null> {
    await this.queue
    const values = await this.readValues()
    return values[grantId] ?? null
  }

  async put(value: StoredGrantAuthorization): Promise<void> {
    const write = this.queue.then(async () => {
      const values = await this.readValues()
      values[value.grantId] = value
      await mkdir(dirname(this.filePath), { recursive: true })
      const temporaryPath = `${this.filePath}.${process.pid}.tmp`
      await writeFile(temporaryPath, `${JSON.stringify(values)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
      })
      await rename(temporaryPath, this.filePath)
    })
    this.queue = write.catch(() => {})
    await write
  }

  private async readValues(): Promise<Record<string, StoredGrantAuthorization>> {
    try {
      const raw = await readFile(this.filePath, 'utf8')
      return JSON.parse(raw) as Record<string, StoredGrantAuthorization>
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
      throw error
    }
  }
}

export type RedisCommandClient = {
  sendCommand(command: readonly string[]): Promise<unknown>
}

export type RedisGrantAuthorizationStoreOptions = {
  client: RedisCommandClient
  keyPrefix?: string
  lockTtlMs?: number
  waitTimeoutMs?: number
  pollIntervalMs?: number
  resultTtlMs?: number
}

// 多副本 Sidecar 使用 Redis 锁住「校验 Grant → 签名 → 保存结果」整个临界区。
// 客户端只需提供通用 sendCommand，node-redis、ioredis 或托管 Redis 适配器均可接入。
export class RedisGrantAuthorizationStore implements GrantAuthorizationStore {
  private readonly prefix: string
  private readonly lockTtlMs: number
  private readonly waitTimeoutMs: number
  private readonly pollIntervalMs: number
  private readonly resultTtlMs: number

  constructor(private readonly options: RedisGrantAuthorizationStoreOptions) {
    this.prefix = options.keyPrefix ?? 'stableops:agent-signer:'
    this.lockTtlMs = options.lockTtlMs ?? 120_000
    this.waitTimeoutMs = options.waitTimeoutMs ?? 15_000
    this.pollIntervalMs = options.pollIntervalMs ?? 50
    this.resultTtlMs = options.resultTtlMs ?? 30 * 24 * 60 * 60_000
    for (const [name, value] of [
      ['lockTtlMs', this.lockTtlMs],
      ['waitTimeoutMs', this.waitTimeoutMs],
      ['pollIntervalMs', this.pollIntervalMs],
      ['resultTtlMs', this.resultTtlMs],
    ] as const) {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error(`${name} must be a positive integer`)
      }
    }
  }

  async get(grantId: string): Promise<StoredGrantAuthorization | null> {
    const raw = await this.options.client.sendCommand(['GET', this.resultKey(grantId)])
    if (raw === null || raw === undefined) return null
    if (typeof raw !== 'string') throw new Error('Redis authorization result is not a string')
    return parseStoredAuthorization(raw, grantId)
  }

  async put(value: StoredGrantAuthorization): Promise<void> {
    await this.putCanonical(value)
  }

  private async putCanonical(value: StoredGrantAuthorization): Promise<StoredGrantAuthorization> {
    const raw = JSON.stringify(value)
    const existing = await this.options.client.sendCommand([
      'EVAL',
      "local v=redis.call('GET',KEYS[1]); if v then return v end; redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[2]); return ''",
      '1',
      this.resultKey(value.grantId),
      raw,
      String(this.resultTtlMs),
    ])
    if (typeof existing === 'string' && existing.length > 0) {
      const canonical = parseStoredAuthorization(existing, value.grantId)
      assertSameGrant(canonical, value.grantTokenHash)
      return canonical
    }
    if (existing !== '') throw new Error('Redis authorization result write returned invalid data')
    return value
  }

  async getOrCreate(
    grantId: string,
    grantTokenHash: string,
    create: () => Promise<StoredGrantAuthorization>,
  ): Promise<StoredGrantAuthorization> {
    const deadline = Date.now() + this.waitTimeoutMs
    while (Date.now() < deadline) {
      const existing = await this.get(grantId)
      if (existing) {
        assertSameGrant(existing, grantTokenHash)
        return existing
      }

      const lockToken = randomUUID()
      const acquired = await this.options.client.sendCommand([
        'SET',
        this.lockKey(grantId),
        lockToken,
        'NX',
        'PX',
        String(this.lockTtlMs),
      ])
      if (acquired === 'OK') {
        const renewal = this.renewLock(grantId, lockToken)
        try {
          const afterLock = await this.get(grantId)
          if (afterLock) {
            assertSameGrant(afterLock, grantTokenHash)
            return afterLock
          }
          const created = await create()
          if (created.grantId !== grantId || created.grantTokenHash !== grantTokenHash) {
            throw new Error('created authorization does not match the claimed grant')
          }
          return await this.putCanonical(created)
        } finally {
          renewal.stop()
          await renewal.done
          await this.releaseLock(grantId, lockToken)
        }
      }
      await delay(this.pollIntervalMs)
    }
    throw new AgentSignerError(
      'authorization store is busy; retry the same grant',
      'authorization_store_busy',
      503,
    )
  }

  private resultKey(grantId: string): string {
    return `${this.prefix}result:${grantId}`
  }

  private lockKey(grantId: string): string {
    return `${this.prefix}lock:${grantId}`
  }

  private async releaseLock(grantId: string, token: string): Promise<void> {
    await this.options.client.sendCommand([
      'EVAL',
      "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
      '1',
      this.lockKey(grantId),
      token,
    ])
  }

  private renewLock(grantId: string, token: string): { stop: () => void; done: Promise<void> } {
    let stop!: () => void
    const stopped = new Promise<void>((resolve) => {
      stop = resolve
    })
    const intervalMs = Math.max(1, Math.floor(this.lockTtlMs / 3))
    const done = (async () => {
      while (await waitForRenewal(intervalMs, stopped)) {
        try {
          const renewed = await this.options.client.sendCommand([
            'EVAL',
            "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) else return 0 end",
            '1',
            this.lockKey(grantId),
            token,
            String(this.lockTtlMs),
          ])
          if (renewed !== 1) return
        } catch {
          // Redis 短暂故障时租约可能丢失；最终仍以原子写入选出的规范结果为准。
          return
        }
      }
    })()
    return { stop, done }
  }
}

function parseStoredAuthorization(raw: string, grantId: string): StoredGrantAuthorization {
  const value = JSON.parse(raw) as Partial<StoredGrantAuthorization>
  if (
    !value ||
    typeof value !== 'object' ||
    value.grantId !== grantId ||
    typeof value.grantTokenHash !== 'string' ||
    typeof value.authorizationId !== 'string' ||
    typeof value.walletAddress !== 'string' ||
    typeof value.typedDataHash !== 'string' ||
    !value.payload ||
    typeof value.payload !== 'object'
  ) {
    throw new Error('Redis authorization result is invalid')
  }
  return value as StoredGrantAuthorization
}

function assertSameGrant(value: StoredGrantAuthorization, grantTokenHash: string): void {
  if (value.grantTokenHash !== grantTokenHash) throw new GrantReplayConflictError()
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function waitForRenewal(milliseconds: number, stopped: Promise<void>): Promise<boolean> {
  return Promise.race([delay(milliseconds).then(() => true), stopped.then(() => false)])
}
