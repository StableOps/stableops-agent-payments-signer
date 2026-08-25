import { lstat, readFile } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import type { Readable } from 'node:stream'
import type { Hex } from 'viem'

import { AwsKmsSigner } from './aws-kms-signer'
import { LocalTestSigner } from './local-signer'
import { LocalSvmSigner } from './local-svm-signer'
import {
  signWalletPairingChallengeWithAwsKms,
  signWalletPairingChallengeWithLocalEvmKey,
  signWalletPairingChallengeWithLocalSolanaKey,
} from './pairing'
import { startSignerSidecar } from './sidecar'
import { FileGrantAuthorizationStore } from './store'
import { BASE_SEPOLIA_NETWORK, type StableOpsEnvironment } from './types'

type SignerKind = 'local' | 'aws-kms' | 'solana'

export type SignerCliIo = {
  stdin: Pick<Readable, typeof Symbol.asyncIterator>
  stdout: { write(value: string): unknown }
  stderr: { write(value: string): unknown }
}

export async function runSignerCli(
  argv: string[],
  env: NodeJS.ProcessEnv,
  io: SignerCliIo,
): Promise<number> {
  try {
    const [command, ...rawOptions] = argv
    if (!command || command === '--help' || command === '-h' || command === 'help') {
      io.stdout.write(HELP)
      return 0
    }
    const options = parseOptions(rawOptions)
    if (options.help) {
      io.stdout.write(HELP)
      return 0
    }

    if (command === 'pair-wallet') {
      const signerKind = readSignerKind(options.signer ?? env.STABLEOPS_SIGNER_TYPE)
      const message = options.challenge
        ? decodeChallenge(options.challenge)
        : await readStdin(io.stdin)
      const signature = await signPairingChallenge(signerKind, message, env)
      io.stdout.write(`${signature}\n`)
      return 0
    }

    if (command === 'serve') {
      const signerKind = readSignerKind(options.signer ?? env.STABLEOPS_SIGNER_TYPE)
      const environment = readEnvironment(env.STABLEOPS_SIGNER_ENVIRONMENT, signerKind)
      const network = readNetwork(env.STABLEOPS_SIGNER_NETWORK, signerKind)
      const grantKeyId = required(env, 'STABLEOPS_GRANT_KEY_ID')
      const publicKey = await readFile(required(env, 'STABLEOPS_GRANT_PUBLIC_KEY_FILE'), 'utf8')
      const store = new FileGrantAuthorizationStore(
        required(env, 'STABLEOPS_AUTHORIZATION_STORE_FILE'),
      )
      const grantVerification = { publicKeys: { [grantKeyId]: publicKey } }

      const signer =
        signerKind === 'local'
          ? new LocalTestSigner({
              privateKey: await readLocalEvmPrivateKey(env),
              environment,
              network: requireEvmNetwork(network),
              grantVerification,
              store,
            })
          : signerKind === 'aws-kms'
            ? await AwsKmsSigner.create({
                keyId: required(env, 'STABLEOPS_KMS_KEY_ID'),
                walletAddress: required(env, 'STABLEOPS_WALLET_ADDRESS') as `0x${string}`,
                environment,
                network: requireEvmNetwork(network),
                clientConfig: { region: env.AWS_REGION?.trim() || undefined },
                grantVerification,
                store,
              })
            : await LocalSvmSigner.create({
                privateKey: await readSecretFile(env, 'STABLEOPS_SOLANA_PRIVATE_KEY_FILE'),
                environment,
                network: requireSolanaNetwork(network),
                rpcUrl: env.STABLEOPS_SOLANA_RPC_URL?.trim() || undefined,
                grantVerification,
                store,
              })

      const { url } = await startSignerSidecar({
        signer,
        host: env.STABLEOPS_SIDECAR_HOST?.trim() || '127.0.0.1',
        port: readPort(env.STABLEOPS_SIDECAR_PORT),
        authToken: required(env, 'STABLEOPS_SIDECAR_TOKEN'),
      })
      io.stdout.write(`${url}\n`)
      return 0
    }

    throw new Error(`unknown command: ${command}`)
  } catch (error) {
    io.stderr.write(`stableops-agent-payments-signer: ${errorMessage(error)}\n`)
    return 1
  }
}

async function signPairingChallenge(
  signerKind: SignerKind,
  message: string,
  env: NodeJS.ProcessEnv,
): Promise<string> {
  if (signerKind === 'local') {
    return signWalletPairingChallengeWithLocalEvmKey(message, await readLocalEvmPrivateKey(env))
  }
  if (signerKind === 'aws-kms') {
    return signWalletPairingChallengeWithAwsKms(message, {
      keyId: required(env, 'STABLEOPS_KMS_KEY_ID'),
      clientConfig: { region: env.AWS_REGION?.trim() || undefined },
    })
  }
  return signWalletPairingChallengeWithLocalSolanaKey(
    message,
    await readSecretFile(env, 'STABLEOPS_SOLANA_PRIVATE_KEY_FILE'),
  )
}

function parseOptions(values: string[]): {
  signer?: string
  challenge?: string
  help: boolean
} {
  const result: { signer?: string; challenge?: string; help: boolean } = { help: false }
  for (let index = 0; index < values.length; index++) {
    const option = values[index]
    if (option === '--help' || option === '-h') {
      result.help = true
      continue
    }
    if (option !== '--signer' && option !== '--challenge') {
      throw new Error(`unknown option: ${option}`)
    }
    const value = values[++index]
    if (!value) throw new Error(`${option} requires a value`)
    if (option === '--signer') result.signer = value
    else result.challenge = value
  }
  return result
}

function decodeChallenge(value: string): string {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error('--challenge must be unpadded base64url')
  }
  const decoded = Buffer.from(value, 'base64url')
  if (decoded.length === 0 || decoded.toString('base64url') !== value) {
    throw new Error('--challenge is not valid canonical base64url')
  }
  return decoded.toString('utf8')
}

async function readStdin(stdin: SignerCliIo['stdin']): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk))
  const value = Buffer.concat(chunks).toString('utf8')
  if (!value) throw new Error('provide --challenge or pipe the complete challenge to stdin')
  return value
}

function readSignerKind(value: string | undefined): SignerKind {
  const normalized = value?.trim().toLowerCase()
  if (normalized === 'local' || normalized === 'aws-kms' || normalized === 'solana') {
    return normalized
  }
  throw new Error('set --signer to local, aws-kms, or solana')
}

function readEnvironment(value: string | undefined, signerKind: SignerKind): StableOpsEnvironment {
  const normalized = value?.trim().toUpperCase() || (signerKind === 'local' ? 'SANDBOX' : '')
  if (normalized !== 'SANDBOX' && normalized !== 'LIVE') {
    throw new Error('STABLEOPS_SIGNER_ENVIRONMENT must be SANDBOX or LIVE')
  }
  if (signerKind === 'local' && normalized !== 'SANDBOX') {
    throw new Error('the local EVM signer is limited to SANDBOX')
  }
  return normalized
}

function readNetwork(value: string | undefined, signerKind: SignerKind): string {
  const network = value?.trim() || (signerKind === 'local' ? BASE_SEPOLIA_NETWORK : '')
  if (!network) throw new Error('STABLEOPS_SIGNER_NETWORK is required')
  return network
}

function requireEvmNetwork(value: string): `eip155:${number}` {
  if (!/^eip155:\d+$/u.test(value)) throw new Error('signer network must be an EVM CAIP-2 ID')
  return value as `eip155:${number}`
}

function requireSolanaNetwork(value: string): `solana:${string}` {
  if (!/^solana:[1-9A-HJ-NP-Za-km-z]+$/u.test(value)) {
    throw new Error('signer network must be a Solana CAIP-2 ID')
  }
  return value as `solana:${string}`
}

async function readLocalEvmPrivateKey(env: NodeJS.ProcessEnv): Promise<Hex> {
  const value = await readSecretFile(env, 'STABLEOPS_EVM_PRIVATE_KEY_FILE')
  if (/^[0-9a-fA-F]{64}$/u.test(value)) {
    throw new Error(
      'local EVM private key is missing the required 0x prefix. Expected file content: 0x followed by 64 hexadecimal digits',
    )
  }
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value)) {
    throw new Error(
      'local EVM private key has an invalid format. Expected file content: 0x followed by 64 hexadecimal digits',
    )
  }
  return value as Hex
}

async function readSecretFile(env: NodeJS.ProcessEnv, name: string): Promise<string> {
  const filePath = required(env, name)
  if (!isAbsolute(filePath)) throw new Error(`${name} must be an absolute path`)
  const info = await lstat(filePath)
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`${name} must reference a regular file, not a symbolic link`)
  }
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) {
    throw new Error(`${name} must not be accessible by group or other users. Run chmod 600`)
  }
  const value = (await readFile(filePath, 'utf8')).trim()
  if (!value) throw new Error(`${name} references an empty file`)
  return value
}

function readPort(value: string | undefined): number {
  if (!value?.trim()) return 8789
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('STABLEOPS_SIDECAR_PORT must be an integer from 1 to 65535')
  }
  return port
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

const HELP = `StableOps Agent Payments Signer

Usage:
  stableops-agent-payments-signer pair-wallet --signer <local|aws-kms|solana> --challenge <base64url>
  stableops-agent-payments-signer serve --signer <local|aws-kms|solana>

pair-wallet validates one complete, unexpired StableOps wallet pairing challenge before signing.
If --challenge is omitted, the exact challenge is read from standard input.

Run configuration is read from environment variables. Local private keys are read only from
access-restricted files and are never accepted as arguments or environment-variable values.
See https://stableops.dev/docs/agent-payments/signer.
`
