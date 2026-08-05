import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

import type { GrantAuthorizationStore, StoredGrantAuthorization } from './types'

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
