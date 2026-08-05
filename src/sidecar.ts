import { timingSafeEqual } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'

import { AgentSignerError } from './errors'
import type { ExecutionGrantSigner } from './types'

const DEFAULT_MAX_BODY_BYTES = 64 * 1024

export type SignerSidecarOptions = {
  signer: ExecutionGrantSigner
  authToken?: string
  maxBodyBytes?: number
}

export type StartSignerSidecarOptions = SignerSidecarOptions & {
  host?: string
  port?: number
}

export function createSignerSidecar(options: SignerSidecarOptions): Server {
  return createServer((request, response) => {
    handleRequest(request, response, options).catch((error: unknown) => {
      sendError(response, error)
    })
  })
}

export async function startSignerSidecar(
  options: StartSignerSidecarOptions,
): Promise<{ server: Server; url: string }> {
  const host = options.host ?? '127.0.0.1'
  if (!isLoopbackHost(host)) {
    throw new AgentSignerError(
      'signer sidecar only listens on loopback by default',
      'unsafe_listen_address',
    )
  }

  const server = createSignerSidecar(options)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(options.port ?? 0, host, () => resolve())
  })
  const address = server.address()
  if (!address || typeof address === 'string') {
    server.close()
    throw new AgentSignerError('sidecar did not obtain a TCP address', 'listen_failed', 500)
  }
  const urlHost = address.family === 'IPv6' ? `[${address.address}]` : address.address
  return { server, url: `http://${urlHost}:${address.port}` }
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: SignerSidecarOptions,
): Promise<void> {
  if (request.method === 'GET' && request.url === '/health') {
    sendJson(response, 200, { ok: true })
    return
  }
  if (request.method !== 'POST' || request.url !== '/v1/sign') {
    sendJson(response, 404, { error: { code: 'not_found', message: 'route not found' } })
    return
  }
  if (options.authToken && !matchesBearerToken(request, options.authToken)) {
    sendJson(response, 401, {
      error: { code: 'invalid_sidecar_token', message: 'sidecar authorization failed' },
    })
    return
  }

  const raw = await readRequestBody(request, options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES)
  let body: unknown
  try {
    body = JSON.parse(raw)
  } catch {
    throw new AgentSignerError('request body is not valid JSON', 'invalid_json')
  }
  if (
    !body ||
    typeof body !== 'object' ||
    typeof (body as { grant?: unknown }).grant !== 'string'
  ) {
    throw new AgentSignerError('request body must contain a grant string', 'invalid_request')
  }

  const result = await options.signer.sign((body as { grant: string }).grant)
  sendJson(response, 200, result)
}

async function readRequestBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buffer.length
    if (size > maxBytes) {
      throw new AgentSignerError('request body is too large', 'request_too_large', 413)
    }
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function matchesBearerToken(request: IncomingMessage, expected: string): boolean {
  const value = request.headers.authorization
  if (!value?.startsWith('Bearer ')) return false
  const actual = Buffer.from(value.slice(7))
  const target = Buffer.from(expected)
  return actual.length === target.length && timingSafeEqual(actual, target)
}

function sendError(response: ServerResponse, error: unknown): void {
  if (error instanceof AgentSignerError) {
    sendJson(response, error.statusCode, {
      error: { code: error.code, message: error.message },
    })
    return
  }
  sendJson(response, 500, {
    error: { code: 'internal_error', message: 'sidecar signing failed' },
  })
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent) return
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  response.end(JSON.stringify(body))
}

function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost'
}
