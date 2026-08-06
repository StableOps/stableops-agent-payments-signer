import { createHash, sign, verify, type KeyLike } from 'node:crypto'

import { getAddress, isAddress, isHex } from 'viem'

import { GrantBindingError, InvalidGrantError } from './errors'
import {
  EXECUTION_GRANT_AUDIENCE,
  EXECUTION_GRANT_TYPE,
  type ExecutionGrantClaims,
  type ExecutionGrantHeader,
  type StableOpsEnvironment,
  type VerifiedExecutionGrant,
} from './types'

export type GrantVerificationKey = KeyLike | string | Buffer

export type VerifyExecutionGrantOptions = {
  publicKeys: Readonly<Record<string, GrantVerificationKey>>
  expected?: {
    environment?: StableOpsEnvironment
    network?: ExecutionGrantClaims['network']
    walletAddress?: string
  }
  now?: () => number
  clockToleranceSeconds?: number
}

export function verifyExecutionGrant(
  token: string,
  options: VerifyExecutionGrantOptions,
): VerifiedExecutionGrant {
  const segments = token.split('.')
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new InvalidGrantError('execution grant must be a compact JWS')
  }

  const [encodedHeader, encodedClaims, encodedSignature] = segments
  const header = decodeJson<ExecutionGrantHeader>(encodedHeader, 'header')
  if (header.alg !== 'EdDSA' || header.typ !== EXECUTION_GRANT_TYPE || !header.kid) {
    throw new InvalidGrantError('execution grant has unsupported protected headers')
  }

  const publicKey = options.publicKeys[header.kid]
  if (!publicKey) {
    throw new InvalidGrantError('execution grant uses an unknown key ID')
  }

  const signed = Buffer.from(`${encodedHeader}.${encodedClaims}`)
  const signature = decodeBase64Url(encodedSignature, 'signature')
  let valid = false
  try {
    valid = verify(null, signed, publicKey, signature)
  } catch {
    throw new InvalidGrantError('execution grant verification key is invalid')
  }
  if (!valid) {
    throw new InvalidGrantError('execution grant signature is invalid')
  }

  const claims = decodeJson<ExecutionGrantClaims>(encodedClaims, 'claims')
  validateClaims(claims, options)

  return {
    header,
    claims,
    token,
    tokenHash: hashGrantToken(token),
  }
}

export function signExecutionGrant(
  claims: ExecutionGrantClaims,
  options: { keyId: string; privateKey: GrantVerificationKey },
): string {
  validateClaims(claims, {
    now: () => claims.issuedAt,
  })
  const header: ExecutionGrantHeader = {
    alg: 'EdDSA',
    kid: options.keyId,
    typ: EXECUTION_GRANT_TYPE,
  }
  const encodedHeader = encodeJson(header)
  const encodedClaims = encodeJson(claims)
  const signed = Buffer.from(`${encodedHeader}.${encodedClaims}`)
  const signature = sign(null, signed, options.privateKey)
  return `${encodedHeader}.${encodedClaims}.${signature.toString('base64url')}`
}

export function hashGrantToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

function validateClaims(
  claims: ExecutionGrantClaims,
  options: Pick<VerifyExecutionGrantOptions, 'expected' | 'now' | 'clockToleranceSeconds'>,
): void {
  if (!claims || typeof claims !== 'object') {
    throw new InvalidGrantError('execution grant claims must be an object')
  }
  if (claims.issuer !== 'stableops' || claims.audience !== EXECUTION_GRANT_AUDIENCE) {
    throw new InvalidGrantError('execution grant issuer or audience is invalid')
  }
  if (claims.x402Version !== 2 || claims.scheme !== 'exact') {
    throw new InvalidGrantError('execution grant payment scheme is unsupported')
  }

  for (const field of [
    'grantId',
    'organizationId',
    'agentId',
    'intentId',
    'authorizationId',
    'walletId',
    'tokenName',
    'tokenVersion',
  ] as const) {
    if (typeof claims[field] !== 'string' || claims[field].length === 0) {
      throw new InvalidGrantError(`execution grant ${field} is required`)
    }
  }

  if (claims.environment !== 'SANDBOX' && claims.environment !== 'LIVE') {
    throw new InvalidGrantError('execution grant environment is invalid')
  }
  const transferMethod = claims.transferMethod ?? 'eip3009'
  const evm = /^eip155:[1-9]\d*$/u.test(claims.network)
  const svm = /^solana:[1-9A-HJ-NP-Za-km-z]+$/u.test(claims.network)
  if (!evm && !svm) {
    throw new InvalidGrantError('execution grant network is invalid')
  }
  if (evm && transferMethod !== 'eip3009' && transferMethod !== 'permit2') {
    throw new InvalidGrantError('execution grant EVM transfer method is invalid')
  }
  if (svm && transferMethod !== 'svm') {
    throw new InvalidGrantError('execution grant SVM transfer method is invalid')
  }
  if (evm && (!isAddress(claims.walletAddress) || !isAddress(claims.assetContract) || !isAddress(claims.payTo))) {
    throw new InvalidGrantError('execution grant contains an invalid EVM address')
  }
  if (
    svm &&
    ![claims.walletAddress, claims.assetContract, claims.payTo].every((value) =>
      /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u.test(value),
    )
  ) {
    throw new InvalidGrantError('execution grant contains an invalid Solana address')
  }
  if (!/^[1-9]\d*$/u.test(claims.amountAtomic)) {
    throw new InvalidGrantError('execution grant amount must be a positive integer')
  }
  if (!/^\d+$/u.test(claims.validAfter) || !/^[1-9]\d*$/u.test(claims.validBefore)) {
    throw new InvalidGrantError('execution grant authorization validity is invalid')
  }
  if (BigInt(claims.validBefore) <= BigInt(claims.validAfter)) {
    throw new InvalidGrantError('execution grant authorization validity is empty')
  }
  if (
    !isHex(claims.nonce, { strict: true }) ||
    claims.nonce.length !== 66 ||
    !isHex(claims.typedDataHash, { strict: true }) ||
    claims.typedDataHash.length !== 66
  ) {
    throw new InvalidGrantError('execution grant nonce or typed data hash is invalid')
  }
  if (
    !Number.isSafeInteger(claims.issuedAt) ||
    !Number.isSafeInteger(claims.expiresAt) ||
    claims.expiresAt <= claims.issuedAt
  ) {
    throw new InvalidGrantError('execution grant lifetime is invalid')
  }

  const now = options.now?.() ?? Math.floor(Date.now() / 1000)
  const tolerance = options.clockToleranceSeconds ?? 5
  if (claims.issuedAt > now + tolerance) {
    throw new InvalidGrantError('execution grant was issued in the future')
  }
  if (claims.expiresAt <= now - tolerance) {
    throw new InvalidGrantError('execution grant has expired')
  }
  if (BigInt(claims.validBefore) <= BigInt(now - tolerance)) {
    throw new InvalidGrantError('payment authorization has expired')
  }

  const expected = options.expected
  if (expected?.environment && claims.environment !== expected.environment) {
    throw new GrantBindingError('execution grant environment does not match the signer')
  }
  if (expected?.network && claims.network !== expected.network) {
    throw new GrantBindingError('execution grant network does not match the signer')
  }
  if (expected?.walletAddress) {
    const matches = evm
      ? getAddress(claims.walletAddress) === getAddress(expected.walletAddress)
      : claims.walletAddress === expected.walletAddress
    if (!matches) {
      throw new GrantBindingError('execution grant wallet does not match the signer')
    }
  }
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function decodeJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(decodeBase64Url(value, label).toString('utf8')) as T
  } catch {
    throw new InvalidGrantError(`execution grant ${label} is not valid JSON`)
  }
}

function decodeBase64Url(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new InvalidGrantError(`execution grant ${label} is not base64url`)
  }
  return Buffer.from(value, 'base64url')
}
