import { PERMIT2_ADDRESS, permit2WitnessTypes, x402ExactPermit2ProxyAddress } from '@x402/evm'
import {
  getAddress,
  hashTypedData,
  keccak256,
  stringToHex,
  type Address,
  type Hex,
  type TypedDataDefinition,
} from 'viem'

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
  if (claims.transferMethod === 'svm') {
    return keccak256(
      stringToHex(
        JSON.stringify({
          network: claims.network,
          walletAddress: claims.walletAddress,
          assetContract: claims.assetContract,
          payTo: claims.payTo,
          amountAtomic: claims.amountAtomic,
          requirementsExtra: claims.requirementsExtra,
        }),
      ),
    )
  }
  if (claims.transferMethod === 'permit2') {
    return hashTypedData(buildPermit2TypedData(claims))
  }
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

export function buildPermit2TypedData(claims: ExecutionGrantClaims) {
  return {
    domain: {
      name: 'Permit2',
      chainId: parseChainId(claims.network),
      verifyingContract: PERMIT2_ADDRESS,
    },
    types: permit2WitnessTypes,
    primaryType: 'PermitWitnessTransferFrom' as const,
    message: {
      permitted: {
        token: getAddress(claims.assetContract),
        amount: BigInt(claims.amountAtomic),
      },
      spender: x402ExactPermit2ProxyAddress,
      nonce: BigInt(claims.nonce),
      deadline: BigInt(claims.validBefore),
      witness: {
        to: getAddress(claims.payTo),
        validAfter: BigInt(claims.validAfter),
      },
    },
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
