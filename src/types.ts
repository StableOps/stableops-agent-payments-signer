import type { Hex } from 'viem'

export const BASE_SEPOLIA_NETWORK = 'eip155:84532' as const
export const EXECUTION_GRANT_AUDIENCE = 'stableops-agent-signer' as const
export const EXECUTION_GRANT_TYPE = 'stableops-execution-grant+jwt' as const

export type StableOpsEnvironment = 'SANDBOX' | 'LIVE'

export type ExecutionGrantClaims = {
  issuer: 'stableops'
  audience: typeof EXECUTION_GRANT_AUDIENCE
  grantId: string
  organizationId: string
  environment: StableOpsEnvironment
  agentId: string
  intentId: string
  authorizationId: string
  walletId: string
  walletAddress: `0x${string}`
  x402Version: 2
  scheme: 'exact'
  network: `eip155:${number}`
  assetContract: `0x${string}`
  tokenName: string
  tokenVersion: string
  payTo: `0x${string}`
  amountAtomic: string
  validAfter: string
  validBefore: string
  nonce: Hex
  typedDataHash: Hex
  issuedAt: number
  expiresAt: number
}

export type ExecutionGrantHeader = {
  alg: 'EdDSA'
  kid: string
  typ: typeof EXECUTION_GRANT_TYPE
}

export type VerifiedExecutionGrant = {
  header: ExecutionGrantHeader
  claims: ExecutionGrantClaims
  token: string
  tokenHash: string
}

export type SignAuthorizationResult = {
  grantId: string
  authorizationId: string
  walletAddress: `0x${string}`
  typedDataHash: Hex
  authorization: {
    from: `0x${string}`
    to: `0x${string}`
    value: string
    validAfter: string
    validBefore: string
    nonce: Hex
  }
  signature: Hex
}

export type StoredGrantAuthorization = SignAuthorizationResult & {
  grantTokenHash: string
}

export interface GrantAuthorizationStore {
  get(grantId: string): Promise<StoredGrantAuthorization | null>
  put(value: StoredGrantAuthorization): Promise<void>
}

export interface ExecutionGrantSigner {
  sign(grantToken: string): Promise<SignAuthorizationResult>
}
