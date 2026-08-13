import { base58 } from '@scure/base'
import { createKeyPairSignerFromBytes } from '@solana/kit'
import { ExactSvmScheme, toClientSvmSigner } from '@x402/svm'

import { GrantBindingError, GrantReplayConflictError } from './errors'
import { verifyExecutionGrant, type VerifyExecutionGrantOptions } from './grant'
import { assertGrantTypedDataHash } from './typed-data'
import { extractSvmTransactionSignature } from './svm-transaction'
import type {
  ExecutionGrantSigner,
  GrantAuthorizationStore,
  SignAuthorizationResult,
  StableOpsEnvironment,
} from './types'

export type LocalSvmSignerOptions = {
  privateKey: string | Uint8Array
  environment: StableOpsEnvironment
  network: `solana:${string}`
  grantVerification: Omit<VerifyExecutionGrantOptions, 'expected'>
  store: GrantAuthorizationStore
  rpcUrl?: string
}

export class LocalSvmSigner implements ExecutionGrantSigner {
  private readonly inFlight = new Map<
    string,
    { grantTokenHash: string; result: Promise<SignAuthorizationResult> }
  >()

  private constructor(
    private readonly options: LocalSvmSignerOptions,
    private readonly signer: ReturnType<typeof toClientSvmSigner>,
  ) {}

  static async create(options: LocalSvmSignerOptions): Promise<LocalSvmSigner> {
    const bytes = typeof options.privateKey === 'string' ? base58.decode(options.privateKey) : options.privateKey
    const signer = toClientSvmSigner(await createKeyPairSignerFromBytes(bytes))
    return new LocalSvmSigner(options, signer)
  }

  get address(): string {
    return this.signer.address
  }

  async sign(grantToken: string): Promise<SignAuthorizationResult> {
    const verified = verifyExecutionGrant(grantToken, {
      ...this.options.grantVerification,
      expected: {
        environment: this.options.environment,
        network: this.options.network,
        walletAddress: this.signer.address,
      },
    })
    if (verified.claims.transferMethod !== 'svm') {
      throw new GrantBindingError('LocalSvmSigner only accepts SVM execution grants')
    }
    if (this.options.store.getOrCreate) {
      const stored = await this.options.store.getOrCreate(
        verified.claims.grantId,
        verified.tokenHash,
        async () => ({
          ...(await this.signVerifiedGrant(verified, false)),
          grantTokenHash: verified.tokenHash,
        }),
      )
      return stripStoredFields(stored)
    }
    const existing = await this.options.store.get(verified.claims.grantId)
    if (existing) {
      if (existing.grantTokenHash !== verified.tokenHash) throw new GrantReplayConflictError()
      return stripStoredFields(existing)
    }
    const pending = this.inFlight.get(verified.claims.grantId)
    if (pending) {
      if (pending.grantTokenHash !== verified.tokenHash) {
        throw new GrantReplayConflictError()
      }
      return pending.result
    }
    const signing = this.signVerifiedGrant(verified).finally(() => {
      this.inFlight.delete(verified.claims.grantId)
    })
    this.inFlight.set(verified.claims.grantId, {
      grantTokenHash: verified.tokenHash,
      result: signing,
    })
    return signing
  }

  private async signVerifiedGrant(
    verified: ReturnType<typeof verifyExecutionGrant>,
    persist = true,
  ): Promise<SignAuthorizationResult> {
    const claims = verified.claims
    const typedDataHash = assertGrantTypedDataHash(claims)
    const scheme = new ExactSvmScheme(this.signer, { rpcUrl: this.options.rpcUrl })
    const requirement: Parameters<ExactSvmScheme['createPaymentPayload']>[1] = {
      scheme: 'exact',
      network: claims.network,
      asset: claims.assetContract,
      amount: claims.amountAtomic,
      payTo: claims.payTo,
      maxTimeoutSeconds: Math.max(1, Number(BigInt(claims.validBefore) - BigInt(claims.validAfter))),
      extra: claims.requirementsExtra ?? {},
    }
    const signed = await scheme.createPaymentPayload(2, requirement)
    const payload = signed.payload as { transaction: string }
    const result: SignAuthorizationResult = {
      grantId: claims.grantId,
      authorizationId: claims.authorizationId,
      walletAddress: this.signer.address,
      typedDataHash,
      payload,
      transactionHash: extractSvmTransactionSignature(payload.transaction),
    }
    if (persist) {
      await this.options.store.put({ ...result, grantTokenHash: verified.tokenHash })
    }
    return result
  }
}

function stripStoredFields(
  value: Awaited<ReturnType<GrantAuthorizationStore['get']>> & object,
): SignAuthorizationResult {
  const { grantTokenHash: _grantTokenHash, ...result } = value
  return result
}
