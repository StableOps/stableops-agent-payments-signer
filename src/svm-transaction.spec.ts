import { base58 } from '@scure/base'
import { describe, expect, it } from 'vitest'

import { extractSvmTransactionSignature } from './svm-transaction'

describe('extractSvmTransactionSignature', () => {
  it('从 Solana wire transaction 提取第一条签名', () => {
    const signature = Uint8Array.from({ length: 64 }, (_, index) => index + 1)
    const transaction = Buffer.concat([Buffer.from([1]), Buffer.from(signature), Buffer.alloc(80)])

    expect(extractSvmTransactionSignature(transaction.toString('base64'))).toBe(
      base58.encode(signature),
    )
  })

  it('拒绝缺少签名或仅含零签名的交易', () => {
    expect(() => extractSvmTransactionSignature(Buffer.from([0]).toString('base64'))).toThrow()
    expect(() =>
      extractSvmTransactionSignature(Buffer.concat([Buffer.from([1]), Buffer.alloc(64)]).toString('base64')),
    ).toThrow()
  })
})
