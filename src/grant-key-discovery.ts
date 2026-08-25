import { createPublicKey, type KeyObject } from 'node:crypto'
import { readFile } from 'node:fs/promises'

const DEFAULT_API_URL = 'https://api.stableops.dev'
const GRANT_KEYS_PATH = '/v1/public/agent-payments/execution-grant-keys'

export async function loadGrantVerificationKeys(
  env: NodeJS.ProcessEnv,
  fetchImpl: typeof fetch = fetch.bind(globalThis),
): Promise<Readonly<Record<string, string | KeyObject>>> {
  const keyId = env.STABLEOPS_GRANT_KEY_ID?.trim()
  const publicKeyFile = env.STABLEOPS_GRANT_PUBLIC_KEY_FILE?.trim()
  if (keyId || publicKeyFile) {
    if (!keyId || !publicKeyFile) {
      throw new Error(
        'STABLEOPS_GRANT_KEY_ID and STABLEOPS_GRANT_PUBLIC_KEY_FILE must be configured together',
      )
    }
    return { [keyId]: await readFile(publicKeyFile, 'utf8') }
  }

  const baseUrl = validateApiUrl(env.STABLEOPS_API_URL?.trim() || DEFAULT_API_URL)
  const url = `${baseUrl}${GRANT_KEYS_PATH}`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10_000)
  let response: Response
  try {
    response = await fetchImpl(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    })
  } catch (error) {
    const message =
      error instanceof DOMException && error.name === 'AbortError'
        ? 'request timed out'
        : error instanceof Error
          ? error.message
          : String(error)
    throw new Error(`failed to fetch execution grant verification keys: ${message}`)
  } finally {
    clearTimeout(timer)
  }
  if (!response.ok) {
    throw new Error(
      `failed to fetch execution grant verification keys: API returned HTTP ${response.status}`,
    )
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new Error('execution grant verification key endpoint returned invalid JSON')
  }
  return parseJwks(payload)
}

function parseJwks(payload: unknown): Readonly<Record<string, KeyObject>> {
  if (!isRecord(payload) || !Array.isArray(payload.keys) || payload.keys.length === 0) {
    throw new Error('execution grant verification key endpoint returned an empty JWKS')
  }
  const result = Object.create(null) as Record<string, KeyObject>
  for (const value of payload.keys) {
    if (
      !isRecord(value) ||
      value.kty !== 'OKP' ||
      value.crv !== 'Ed25519' ||
      value.alg !== 'EdDSA' ||
      value.use !== 'sig' ||
      typeof value.kid !== 'string' ||
      !value.kid.trim() ||
      typeof value.x !== 'string'
    ) {
      throw new Error('execution grant verification key endpoint returned an invalid Ed25519 key')
    }
    const decoded = Buffer.from(value.x, 'base64url')
    if (decoded.length !== 32 || decoded.toString('base64url') !== value.x) {
      throw new Error('execution grant verification key endpoint returned an invalid Ed25519 key')
    }
    if (Object.hasOwn(result, value.kid)) {
      throw new Error('execution grant verification key endpoint returned a duplicate key ID')
    }
    try {
      result[value.kid] = createPublicKey({
        key: { kty: value.kty, crv: value.crv, x: value.x },
        format: 'jwk',
      })
    } catch {
      throw new Error('execution grant verification key endpoint returned an invalid Ed25519 key')
    }
  }
  return result
}

function validateApiUrl(value: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error('STABLEOPS_API_URL is invalid')
  }
  const loopback =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'
  if (
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) ||
    url.username ||
    url.password
  ) {
    throw new Error('STABLEOPS_API_URL must use HTTPS without user information')
  }
  return value.replace(/\/+$/u, '')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}
