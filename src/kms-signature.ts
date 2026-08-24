import {
  GetPublicKeyCommand,
  SignCommand,
  type GetPublicKeyCommandOutput,
  type SignCommandOutput,
} from '@aws-sdk/client-kms'
import { createPublicKey } from 'node:crypto'
import { concatHex, getAddress, numberToHex, recoverAddress, type Hex } from 'viem'
import { publicKeyToAddress } from 'viem/accounts'

import { GrantBindingError } from './errors'

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const SECP256K1_HALF_ORDER = SECP256K1_ORDER / 2n

export interface KmsSigningClient {
  send(command: GetPublicKeyCommand): Promise<GetPublicKeyCommandOutput>
  send(command: SignCommand): Promise<SignCommandOutput>
}

export async function loadKmsSigningAddress(
  client: KmsSigningClient,
  keyId: string,
): Promise<`0x${string}`> {
  const response = await client.send(new GetPublicKeyCommand({ KeyId: keyId }))
  if (
    response.KeySpec !== 'ECC_SECG_P256K1' ||
    response.KeyUsage !== 'SIGN_VERIFY' ||
    !response.SigningAlgorithms?.includes('ECDSA_SHA_256') ||
    !response.PublicKey
  ) {
    throw new GrantBindingError(
      'AWS KMS key must be ECC_SECG_P256K1 with SIGN_VERIFY and ECDSA_SHA_256',
    )
  }
  return addressFromSubjectPublicKeyInfo(response.PublicKey)
}

export function decodeKmsDerSignature(value: Uint8Array): { r: bigint; s: bigint } {
  let offset = 0
  if (value[offset++] !== 0x30) throw new GrantBindingError('invalid AWS KMS DER signature')
  const sequence = readDerLength(value, offset)
  offset = sequence.offset
  if (offset + sequence.length !== value.length) {
    throw new GrantBindingError('invalid AWS KMS DER signature length')
  }
  const r = readDerInteger(value, offset)
  const s = readDerInteger(value, r.offset)
  if (s.offset !== value.length || r.value <= 0n || s.value <= 0n) {
    throw new GrantBindingError('invalid AWS KMS DER signature values')
  }
  return { r: r.value, s: s.value }
}

export function normalizeLowS(value: bigint): bigint {
  if (value <= 0n || value >= SECP256K1_ORDER) {
    throw new GrantBindingError('AWS KMS signature s value is outside secp256k1 range')
  }
  return value > SECP256K1_HALF_ORDER ? SECP256K1_ORDER - value : value
}

export async function recoverableEthereumSignature(
  hash: Hex,
  derSignature: Uint8Array,
  expectedAddress: `0x${string}`,
): Promise<Hex> {
  const decoded = decodeKmsDerSignature(derSignature)
  if (decoded.r >= SECP256K1_ORDER) {
    throw new GrantBindingError('AWS KMS signature r value is outside secp256k1 range')
  }
  const r = numberToHex(decoded.r, { size: 32 })
  const s = numberToHex(normalizeLowS(decoded.s), { size: 32 })
  for (const recovery of [27, 28] as const) {
    const signature = concatHex([r, s, numberToHex(recovery, { size: 1 })])
    const recovered = await recoverAddress({ hash, signature })
    if (getAddress(recovered) === getAddress(expectedAddress)) return signature
  }
  throw new GrantBindingError('AWS KMS signature does not recover to the configured wallet')
}

function addressFromSubjectPublicKeyInfo(value: Uint8Array): `0x${string}` {
  let key
  try {
    key = createPublicKey({
      key: Buffer.from(value),
      format: 'der',
      type: 'spki',
    })
  } catch {
    throw new GrantBindingError('AWS KMS returned an invalid public key')
  }
  const jwk = key.export({ format: 'jwk' })
  if (jwk.crv !== 'secp256k1' || !jwk.x || !jwk.y) {
    throw new GrantBindingError('AWS KMS public key is not secp256k1')
  }
  const publicKey = `0x04${Buffer.from(jwk.x, 'base64url').toString('hex')}${Buffer.from(
    jwk.y,
    'base64url',
  ).toString('hex')}` as Hex
  return getAddress(publicKeyToAddress(publicKey))
}

function readDerLength(value: Uint8Array, offset: number) {
  const first = value[offset]
  if (first === undefined) throw new GrantBindingError('invalid AWS KMS DER signature')
  if ((first & 0x80) === 0) return { length: first, offset: offset + 1 }
  const size = first & 0x7f
  if (size === 0 || size > 2 || offset + size >= value.length) {
    throw new GrantBindingError('invalid AWS KMS DER signature length')
  }
  let length = 0
  for (let index = 0; index < size; index++) {
    length = (length << 8) | value[offset + 1 + index]!
  }
  return { length, offset: offset + 1 + size }
}

function readDerInteger(value: Uint8Array, offset: number) {
  if (value[offset++] !== 0x02) throw new GrantBindingError('invalid AWS KMS DER integer')
  const integer = readDerLength(value, offset)
  offset = integer.offset
  if (integer.length === 0 || integer.length > 33 || offset + integer.length > value.length) {
    throw new GrantBindingError('invalid AWS KMS DER integer length')
  }
  const bytes = value.slice(offset, offset + integer.length)
  if ((bytes[0]! & 0x80) !== 0) throw new GrantBindingError('negative AWS KMS DER integer')
  if (bytes.length > 1 && bytes[0] === 0 && (bytes[1]! & 0x80) === 0) {
    throw new GrantBindingError('non-canonical AWS KMS DER integer')
  }
  const normalized = bytes[0] === 0 ? bytes.slice(1) : bytes
  const hex = Buffer.from(normalized).toString('hex') || '0'
  return {
    value: BigInt(`0x${hex}`),
    offset: offset + integer.length,
  }
}
