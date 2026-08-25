import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { verifyMessage } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { afterEach, describe, expect, it } from 'vitest'

import { runSignerCli, type SignerCliIo } from './cli'

const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const
const TEST_ACCOUNT = privateKeyToAccount(TEST_PRIVATE_KEY)
const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  )
})

describe('StableOps Agent Payments Signer CLI', () => {
  it('从 base64url 质询生成可验证的钱包配对签名，标准输出不混入提示信息', async () => {
    const message = pairingMessage({ expiresAt: '2099-08-24T14:53:26.643Z' })
    const output = createIo()
    const env = await localSignerEnv()

    const exitCode = await runSignerCli(
      [
        'pair-wallet',
        '--signer',
        'local',
        '--challenge',
        Buffer.from(message).toString('base64url'),
      ],
      env,
      output.io,
    )

    expect(exitCode).toBe(0)
    expect(output.stderr).toBe('')
    expect(output.stdout).toMatch(/^0x[0-9a-f]{130}\n$/u)
    await expect(
      verifyMessage({
        address: TEST_ACCOUNT.address,
        message,
        signature: output.stdout.trim() as `0x${string}`,
      }),
    ).resolves.toBe(true)
  })

  it('接受标准输入末尾的一个换行符', async () => {
    const message = pairingMessage({ expiresAt: '2099-08-24T14:53:26.643Z' })
    const output = createIo()
    output.io.stdin = Readable.from([`${message}\n`])
    const env = await localSignerEnv()

    const exitCode = await runSignerCli(['pair-wallet', '--signer', 'local'], env, output.io)

    expect(exitCode).toBe(0)
    expect(output.stderr).toBe('')
    expect(output.stdout).toMatch(/^0x[0-9a-f]{130}\n$/u)
    await expect(
      verifyMessage({
        address: TEST_ACCOUNT.address,
        message,
        signature: output.stdout.trim() as `0x${string}`,
      }),
    ).resolves.toBe(true)
  })

  it('拒绝过期质询且不输出签名', async () => {
    const message = pairingMessage({ expiresAt: '2020-08-24T14:53:26.643Z' })
    const output = createIo()
    const env = await localSignerEnv()

    const exitCode = await runSignerCli(
      [
        'pair-wallet',
        '--signer',
        'local',
        '--challenge',
        Buffer.from(message).toString('base64url'),
      ],
      env,
      output.io,
    )

    expect(exitCode).toBe(1)
    expect(output.stdout).toBe('')
    expect(output.stderr).toContain('pairing challenge has expired')
  })

  it('拒绝与本地私钥不匹配的钱包地址', async () => {
    const message = pairingMessage({
      address: '0x0000000000000000000000000000000000000001',
      expiresAt: '2099-08-24T14:53:26.643Z',
    })
    const output = createIo()
    const env = await localSignerEnv()

    const exitCode = await runSignerCli(
      [
        'pair-wallet',
        '--signer',
        'local',
        '--challenge',
        Buffer.from(message).toString('base64url'),
      ],
      env,
      output.io,
    )

    expect(exitCode).toBe(1)
    expect(output.stdout).toBe('')
    expect(output.stderr).toContain('does not control the challenge address')
  })

  it.skipIf(process.platform === 'win32')('拒绝读取向组或其他用户开放的私钥文件', async () => {
    const message = pairingMessage({ expiresAt: '2099-08-24T14:53:26.643Z' })
    const output = createIo()
    const env = await localSignerEnv()
    await chmod(env.STABLEOPS_EVM_PRIVATE_KEY_FILE!, 0o644)

    const exitCode = await runSignerCli(
      [
        'pair-wallet',
        '--signer',
        'local',
        '--challenge',
        Buffer.from(message).toString('base64url'),
      ],
      env,
      output.io,
    )

    expect(exitCode).toBe(1)
    expect(output.stdout).toBe('')
    expect(output.stderr).toContain('must not be accessible by group or other users')
  })

  it('私钥缺少 0x 前缀时给出可操作的错误提示', async () => {
    const message = pairingMessage({ expiresAt: '2099-08-24T14:53:26.643Z' })
    const output = createIo()
    const env = await localSignerEnv()
    await writeFile(env.STABLEOPS_EVM_PRIVATE_KEY_FILE!, `${TEST_PRIVATE_KEY.slice(2)}\n`, {
      mode: 0o600,
    })

    const exitCode = await runSignerCli(
      [
        'pair-wallet',
        '--signer',
        'local',
        '--challenge',
        Buffer.from(message).toString('base64url'),
      ],
      env,
      output.io,
    )

    expect(exitCode).toBe(1)
    expect(output.stdout).toBe('')
    expect(output.stderr).toContain('missing the required 0x prefix')
    expect(output.stderr).not.toContain(TEST_PRIVATE_KEY.slice(2))
  })
})

function pairingMessage({
  address = TEST_ACCOUNT.address,
  expiresAt,
}: {
  address?: string
  expiresAt: string
}): string {
  return [
    'StableOps Agent Wallet Pairing',
    'Organization: org_test',
    'Environment: SANDBOX',
    'Network: eip155:84532',
    `Address: ${address}`,
    `Nonce: ${'12'.repeat(32)}`,
    `Expires At: ${expiresAt}`,
  ].join('\n')
}

function createIo(): { io: SignerCliIo; stdout: string; stderr: string } {
  const result = {
    stdout: '',
    stderr: '',
    io: undefined as unknown as SignerCliIo,
  }
  result.io = {
    stdin: Readable.from([]),
    stdout: { write: (value) => (result.stdout += value) },
    stderr: { write: (value) => (result.stderr += value) },
  }
  return result
}

async function localSignerEnv(): Promise<NodeJS.ProcessEnv> {
  const directory = await mkdtemp(join(tmpdir(), 'stableops-signer-cli-'))
  temporaryDirectories.push(directory)
  const filePath = join(directory, 'evm-private-key')
  await writeFile(filePath, `${TEST_PRIVATE_KEY}\n`, { mode: 0o600 })
  await chmod(filePath, 0o600)
  return { STABLEOPS_EVM_PRIVATE_KEY_FILE: filePath }
}
