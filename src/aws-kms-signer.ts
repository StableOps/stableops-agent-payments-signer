import { KMSClient, SignCommand, type KMSClientConfig } from '@aws-sdk/client-kms'
import { x402ExactPermit2ProxyAddress } from '@x402/evm'
import { getAddress, hexToBytes } from 'viem'

import { GrantBindingError, GrantReplayConflictError } from './errors'
import { verifyExecutionGrant, type VerifyExecutionGrantOptions } from './grant'
import {
  loadKmsSigningAddress,
  recoverableEthereumSignature,
  type KmsSigningClient,
} from './kms-signature'
import { assertGrantTypedDataHash } from './typed-data'
import {
  BASE_SEPOLIA_NETWORK,
  type StableOpsEnvironment,
  type ExecutionGrantSigner,
  type GrantAuthorizationStore,
  type SignAuthorizationResult,
} from './types'

export { decodeKmsDerSignature, normalizeLowS, type KmsSigningClient } from './kms-signature'

export type AwsKmsSignerOptions = {
  keyId: string
  walletAddress: `0x${string}`
  environment?: StableOpsEnvironment
  network?: `eip155:${number}`
  grantVerification: Omit<VerifyExecutionGrantOptions, 'expected'>
  store: GrantAuthorizationStore
  client?: KmsSigningClient
  clientConfig?: KMSClientConfig
}

export class AwsKmsSigner implements ExecutionGrantSigner {
  private readonly inFlight = new Map<
    string,
    { grantTokenHash: string; result: Promise<SignAuthorizationResult> }
  >()

  private constructor(
    private readonly options: AwsKmsSignerOptions,
    private readonly client: KmsSigningClient,
    readonly address: `0x${string}`,
  ) {}

  static async create(options: AwsKmsSignerOptions): Promise<AwsKmsSigner> {
    const client: KmsSigningClient =
      options.client ?? (new KMSClient(options.clientConfig ?? {}) as KmsSigningClient)
    const address = await loadKmsSigningAddress(client, options.keyId)
    if (getAddress(address) !== getAddress(options.walletAddress)) {
      throw new GrantBindingError('AWS KMS public key does not match the configured wallet')
    }
    return new AwsKmsSigner(options, client, address)
  }

  async sign(grantToken: string): Promise<SignAuthorizationResult> {
    const verified = verifyExecutionGrant(grantToken, {
      ...this.options.grantVerification,
      expected: {
        environment: this.options.environment ?? 'SANDBOX',
        network: this.options.network ?? BASE_SEPOLIA_NETWORK,
        walletAddress: this.address,
      },
    })
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
      if (existing.grantTokenHash !== verified.tokenHash) {
        throw new GrantReplayConflictError()
      }
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
    if (claims.transferMethod === 'svm') {
      throw new GrantBindingError('AwsKmsSigner only supports EVM execution grants')
    }
    const typedDataHash = assertGrantTypedDataHash(claims)
    const response = await this.client.send(
      new SignCommand({
        KeyId: this.options.keyId,
        Message: hexToBytes(typedDataHash),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
      }),
    )
    if (!response.Signature || response.SigningAlgorithm !== 'ECDSA_SHA_256') {
      throw new GrantBindingError('AWS KMS did not return an ECDSA_SHA_256 signature')
    }
    const signature = await recoverableEthereumSignature(
      typedDataHash,
      response.Signature,
      this.address,
    )
    const authorization = {
      from: getAddress(claims.walletAddress),
      to: getAddress(claims.payTo),
      value: claims.amountAtomic,
      validAfter: claims.validAfter,
      validBefore: claims.validBefore,
      nonce: claims.nonce,
    }
    const payload =
      claims.transferMethod === 'permit2'
        ? {
            signature,
            permit2Authorization: {
              from: getAddress(claims.walletAddress),
              permitted: {
                token: getAddress(claims.assetContract),
                amount: claims.amountAtomic,
              },
              spender: x402ExactPermit2ProxyAddress,
              nonce: claims.nonce,
              deadline: claims.validBefore,
              witness: { to: getAddress(claims.payTo), validAfter: claims.validAfter },
            },
          }
        : { authorization, signature }
    const result: SignAuthorizationResult = {
      grantId: claims.grantId,
      authorizationId: claims.authorizationId,
      walletAddress: this.address,
      typedDataHash,
      payload,
      ...(claims.transferMethod === 'permit2' ? {} : { authorization }),
      signature,
    }
    if (persist) {
      await this.options.store.put({
        ...result,
        grantTokenHash: verified.tokenHash,
      })
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
