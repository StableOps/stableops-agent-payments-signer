import { base58 } from '@scure/base'

export function extractSvmTransactionSignature(encodedTransaction: string): string {
  const transaction = Buffer.from(encodedTransaction, 'base64')
  let signatureCount = 0
  let shift = 0
  let offset = 0
  for (; offset < transaction.length && offset < 3; offset++) {
    const byte = transaction[offset]
    signatureCount |= (byte & 0x7f) << shift
    if ((byte & 0x80) === 0) {
      offset++
      break
    }
    shift += 7
  }
  if (
    signatureCount < 1 ||
    shift > 14 ||
    transaction.length < offset + 64
  ) {
    throw new Error('signed SVM transaction does not contain a valid signature')
  }
  const signature = transaction.subarray(offset, offset + 64)
  if (signature.every((byte) => byte === 0)) {
    throw new Error('signed SVM transaction contains an empty signature')
  }
  return base58.encode(signature)
}
