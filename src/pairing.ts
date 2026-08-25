import { KMSClient, SignCommand, type KMSClientConfig } from '@aws-sdk/client-kms'
import { base58 } from '@scure/base'
import { createKeyPairSignerFromBytes, createSignableMessage } from '@solana/kit'
import { getAddress, hashMessage, hexToBytes, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { AgentSignerError } from './errors'
import {
  loadKmsSigningAddress,
  recoverableEthereumSignature,
  type KmsSigningClient,
} from './kms-signature'
import type { StableOpsEnvironment } from './types'

export type WalletPairingChallenge = {
  organizationId: string
  environment: StableOpsEnvironment
  network: `eip155:${number}` | `solana:${string}`
  address: string
  nonce: string
  expiresAt: Date
  message: string
}

export function parseWalletPairingChallenge(
  message: string,
  now: Date = new Date(),
): WalletPairingChallenge {
  // 终端标准输入通常会在最后一行追加换行，Windows 剪贴板也可能使用 CRLF。
  // 只移除一个末尾换行，不放宽中间的行数、缩进或字段格式校验。
  const normalizedMessage = message.replace(/\r\n/gu, '\n').replace(/\n$/u, '')
  const lines = normalizedMessage.split('\n')
  if (lines.length !== 7 || lines[0] !== 'StableOps Agent Wallet Pairing') {
    throw pairingError('input is not a complete StableOps wallet pairing challenge')
  }

  const organizationId = readField(lines[1], 'Organization')
  const environment = readField(lines[2], 'Environment')
  const network = readField(lines[3], 'Network')
  const address = readField(lines[4], 'Address')
  const nonce = readField(lines[5], 'Nonce')
  const expiresAtValue = readField(lines[6], 'Expires At')

  if (environment !== 'SANDBOX' && environment !== 'LIVE') {
    throw pairingError('pairing challenge environment is invalid')
  }
  if (!/^eip155:\d+$/u.test(network) && !/^solana:[1-9A-HJ-NP-Za-km-z]+$/u.test(network)) {
    throw pairingError('pairing challenge network is invalid')
  }
  if (!/^[0-9a-f]{64}$/u.test(nonce)) {
    throw pairingError('pairing challenge nonce is invalid')
  }
  const expiresAt = new Date(expiresAtValue)
  if (Number.isNaN(expiresAt.getTime()) || expiresAt.toISOString() !== expiresAtValue) {
    throw pairingError('pairing challenge expiry is invalid')
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw pairingError('pairing challenge has expired')
  }

  if (network.startsWith('eip155:')) {
    try {
      getAddress(address)
    } catch {
      throw pairingError('pairing challenge contains an invalid EVM address')
    }
  } else {
    try {
      if (base58.decode(address).length !== 32) throw new Error('invalid length')
    } catch {
      throw pairingError('pairing challenge contains an invalid Solana address')
    }
  }

  return {
    organizationId,
    environment,
    network: network as WalletPairingChallenge['network'],
    address,
    nonce,
    expiresAt,
    message: normalizedMessage,
  }
}

export async function signWalletPairingChallengeWithLocalEvmKey(
  message: string,
  privateKey: Hex,
  now?: Date,
): Promise<Hex> {
  const challenge = parseWalletPairingChallenge(message, now)
  if (!challenge.network.startsWith('eip155:')) {
    throw pairingError('the local EVM signer cannot sign a Solana pairing challenge')
  }
  if (challenge.environment !== 'SANDBOX') {
    throw pairingError('the local EVM signer is limited to Sandbox pairing challenges')
  }
  const account = privateKeyToAccount(privateKey)
  if (getAddress(account.address) !== getAddress(challenge.address)) {
    throw pairingError('the local EVM key does not control the challenge address')
  }
  return account.signMessage({ message: challenge.message })
}

export async function signWalletPairingChallengeWithLocalSolanaKey(
  message: string,
  privateKey: string,
  now?: Date,
): Promise<string> {
  const challenge = parseWalletPairingChallenge(message, now)
  if (!challenge.network.startsWith('solana:')) {
    throw pairingError('the local Solana signer cannot sign an EVM pairing challenge')
  }
  const signer = await createKeyPairSignerFromBytes(base58.decode(privateKey))
  if (signer.address !== challenge.address) {
    throw pairingError('the local Solana key does not control the challenge address')
  }
  const [signatures] = await signer.signMessages([createSignableMessage(challenge.message)])
  const signature = signatures?.[signer.address]
  if (!signature) throw pairingError('the local Solana signer did not return a signature')
  return base58.encode(signature)
}

export async function signWalletPairingChallengeWithAwsKms(
  message: string,
  options: {
    keyId: string
    client?: KmsSigningClient
    clientConfig?: KMSClientConfig
    now?: Date
  },
): Promise<Hex> {
  const challenge = parseWalletPairingChallenge(message, options.now)
  if (!challenge.network.startsWith('eip155:')) {
    throw pairingError('the AWS KMS signer cannot sign a Solana pairing challenge')
  }
  const client: KmsSigningClient =
    options.client ?? (new KMSClient(options.clientConfig ?? {}) as KmsSigningClient)
  const address = await loadKmsSigningAddress(client, options.keyId)
  if (getAddress(address) !== getAddress(challenge.address)) {
    throw pairingError('the AWS KMS key does not control the challenge address')
  }
  const digest = hashMessage(challenge.message)
  const response = await client.send(
    new SignCommand({
      KeyId: options.keyId,
      Message: hexToBytes(digest),
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    }),
  )
  if (!response.Signature || response.SigningAlgorithm !== 'ECDSA_SHA_256') {
    throw pairingError('AWS KMS did not return an ECDSA_SHA_256 signature')
  }
  return recoverableEthereumSignature(digest, response.Signature, address)
}

function readField(line: string | undefined, name: string): string {
  const prefix = `${name}: `
  if (!line?.startsWith(prefix) || line.length === prefix.length) {
    throw pairingError(`pairing challenge ${name} field is invalid`)
  }
  return line.slice(prefix.length)
}

function pairingError(message: string): AgentSignerError {
  return new AgentSignerError(message, 'invalid_pairing_challenge')
}
