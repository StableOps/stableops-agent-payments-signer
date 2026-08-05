import { getAddress, hashTypedData, type Address, type Hex, type TypedDataDefinition } from 'viem'

import { GrantBindingError } from './errors'
import type { ExecutionGrantClaims } from './types'

export const transferWithAuthorizationTypes = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const

export type TransferWithAuthorizationTypedData = TypedDataDefinition<
  typeof transferWithAuthorizationTypes,
  'TransferWithAuthorization'
>

export function buildTransferWithAuthorizationTypedData(
  claims: ExecutionGrantClaims,
): TransferWithAuthorizationTypedData {
  const chainId = parseChainId(claims.network)

  return {
    domain: {
      name: claims.tokenName,
      version: claims.tokenVersion,
      chainId,
      verifyingContract: getAddress(claims.assetContract),
    },
    types: transferWithAuthorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: getAddress(claims.walletAddress),
      to: getAddress(claims.payTo),
      value: BigInt(claims.amountAtomic),
      validAfter: BigInt(claims.validAfter),
      validBefore: BigInt(claims.validBefore),
      nonce: claims.nonce,
    },
  }
}

export function hashGrantTypedData(claims: ExecutionGrantClaims): Hex {
  return hashTypedData(buildTransferWithAuthorizationTypedData(claims))
}

export function assertGrantTypedDataHash(claims: ExecutionGrantClaims): Hex {
  const actual = hashGrantTypedData(claims)
  if (actual.toLowerCase() !== claims.typedDataHash.toLowerCase()) {
    throw new GrantBindingError('typed data hash does not match the execution grant')
  }
  return actual
}

export function normalizeGrantAddress(value: string): Address {
  try {
    return getAddress(value)
  } catch {
    throw new GrantBindingError('execution grant contains an invalid EVM address')
  }
}

function parseChainId(network: string): number {
  const match = /^eip155:([1-9]\d*)$/u.exec(network)
  if (!match) {
    throw new GrantBindingError('execution grant contains an invalid EVM network')
  }

  const chainId = Number(match[1])
  if (!Number.isSafeInteger(chainId)) {
    throw new GrantBindingError('execution grant chain ID exceeds the safe integer range')
  }
  return chainId
}
