import { getAddress, recoverTypedDataAddress, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import { GrantBindingError, GrantReplayConflictError } from './errors'
import { verifyExecutionGrant, type VerifyExecutionGrantOptions } from './grant'
import { assertGrantTypedDataHash, buildTransferWithAuthorizationTypedData } from './typed-data'
import {
  BASE_SEPOLIA_NETWORK,
  type ExecutionGrantSigner,
  type GrantAuthorizationStore,
  type SignAuthorizationResult,
} from './types'

export type LocalTestSignerOptions = {
  privateKey: Hex
  grantVerification: Omit<VerifyExecutionGrantOptions, 'expected'>
  store: GrantAuthorizationStore
}

export class LocalTestSigner implements ExecutionGrantSigner {
  private readonly account
  private readonly inFlight = new Map<string, Promise<SignAuthorizationResult>>()

  constructor(private readonly options: LocalTestSignerOptions) {
    this.account = privateKeyToAccount(options.privateKey)
  }

  get address(): `0x${string}` {
    return this.account.address
  }

  async sign(grantToken: string): Promise<SignAuthorizationResult> {
    const verified = verifyExecutionGrant(grantToken, {
      ...this.options.grantVerification,
      expected: {
        environment: 'SANDBOX',
        network: BASE_SEPOLIA_NETWORK,
        walletAddress: this.account.address,
      },
    })

    const existing = await this.options.store.get(verified.claims.grantId)
    if (existing) {
      if (existing.grantTokenHash !== verified.tokenHash) {
        throw new GrantReplayConflictError()
      }
      return stripStoredFields(existing)
    }

    const pending = this.inFlight.get(verified.claims.grantId)
    if (pending) return pending

    const signing = this.signVerifiedGrant(verified).finally(() => {
      this.inFlight.delete(verified.claims.grantId)
    })
    this.inFlight.set(verified.claims.grantId, signing)
    return signing
  }

  private async signVerifiedGrant(
    verified: ReturnType<typeof verifyExecutionGrant>,
  ): Promise<SignAuthorizationResult> {
    const claims = verified.claims
    const typedData = buildTransferWithAuthorizationTypedData(claims)
    const typedDataHash = assertGrantTypedDataHash(claims)
    const signature = await this.account.signTypedData(typedData)
    await assertRecoveredAddress(this.account.address, typedData, signature)

    const result: SignAuthorizationResult = {
      grantId: claims.grantId,
      authorizationId: claims.authorizationId,
      walletAddress: this.account.address,
      typedDataHash,
      authorization: {
        from: getAddress(claims.walletAddress),
        to: getAddress(claims.payTo),
        value: claims.amountAtomic,
        validAfter: claims.validAfter,
        validBefore: claims.validBefore,
        nonce: claims.nonce,
      },
      signature,
    }
    await this.options.store.put({
      ...result,
      grantTokenHash: verified.tokenHash,
    })
    return result
  }
}

async function assertRecoveredAddress(
  expected: `0x${string}`,
  typedData: ReturnType<typeof buildTransferWithAuthorizationTypedData>,
  signature: Hex,
): Promise<void> {
  const recovered = await recoverTypedDataAddress({
    ...typedData,
    signature,
  })
  if (getAddress(recovered) !== getAddress(expected)) {
    throw new GrantBindingError('generated signature does not recover to the configured wallet')
  }
}

function stripStoredFields(
  value: Awaited<ReturnType<GrantAuthorizationStore['get']>> & object,
): SignAuthorizationResult {
  const { grantTokenHash: _grantTokenHash, ...result } = value
  return result
}
