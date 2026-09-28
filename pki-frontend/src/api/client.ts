/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

/**
 * Admin API client, layered over the swappable {@link currentTransport}.
 *
 * The SPA is served same-origin by nginx, which terminates the browser's client
 * certificate (mTLS), applies RFC 9440 forwarding, and reverse-proxies to
 * pki-server. The browser sends no bearer token and holds no secret;
 * authentication is the TLS client certificate presented to nginx. Every request
 * is independently authenticated and authorized server-side — the SPA never
 * caches an authorization decision and cannot become authorization authority.
 */
import { currentTransport } from '@/api/transport';

/** Problem-details style error surfaced by the server (or synthesized on transport failure). */
export interface ApiError {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly reason?: string;
  readonly body?: unknown;
}

export class ApiRequestError extends Error implements ApiError {
  readonly status: number;
  readonly code: string;
  readonly reason?: string;
  readonly body?: unknown;

  constructor(e: ApiError) {
    super(e.message);
    this.name = 'ApiRequestError';
    this.status = e.status;
    this.code = e.code;
    if (e.reason !== undefined) this.reason = e.reason;
    if (e.body !== undefined) this.body = e.body;
  }
}

export interface RequestOptions {
  readonly method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  readonly body?: unknown;
  readonly query?: Record<string, string | number | boolean | undefined>;
  readonly signal?: AbortSignal;
  readonly rawText?: boolean;
}

function errorFromBody(status: number, bodyText: string): ApiRequestError {
  let body: unknown;
  let message = `HTTP ${status}`;
  let code = `http_${status}`;
  let reason: string | undefined;
  if (bodyText) {
    try {
      body = JSON.parse(bodyText);
      const b = body as Record<string, unknown>;
      if (typeof b.message === 'string') message = b.message;
      if (typeof b.code === 'string') code = b.code;
      if (typeof b.reason === 'string') reason = b.reason;
      const failure = b.failure as Record<string, unknown> | undefined;
      if (failure) {
        if (typeof failure.code === 'string') code = failure.code;
        if (typeof failure.messageKey === 'string') message = failure.messageKey;
        if (typeof failure.classification === 'string') reason = failure.classification;
      }
    } catch {
      body = bodyText;
      message = bodyText.slice(0, 500);
    }
  }
  return new ApiRequestError({ status, code, message, ...(reason !== undefined ? { reason } : {}), body });
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, query, rawText } = opts;
  const headers: Record<string, string> = { Accept: rawText ? 'text/plain, */*' : 'application/json' };
  const req: Parameters<ReturnType<typeof currentTransport>>[0] = {
    method,
    path,
    query,
    headers,
    body: undefined,
    signal: opts.signal,
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    (req as { body?: string }).body = JSON.stringify(body);
  }

  let res: Awaited<ReturnType<ReturnType<typeof currentTransport>>>;
  try {
    res = await currentTransport()(req);
  } catch (cause) {
    throw new ApiRequestError({
      status: 0,
      code: 'network_error',
      message: cause instanceof Error ? cause.message : 'Network request failed',
    });
  }

  if (res.status < 200 || res.status >= 300) throw errorFromBody(res.status, res.body);
  if (rawText) return res.body as unknown as T;
  if (res.status === 204 || !res.body) return undefined as unknown as T;
  return JSON.parse(res.body) as T;
}

/** Low-level response that retains the envelope AND transport metadata, never throwing on HTTP status. */
export interface RawResult {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

export function postRaw(path: string, body: unknown, signal?: AbortSignal): Promise<RawResult> {
  return requestRaw('POST', path, body, signal);
}

export function getRaw(path: string, signal?: AbortSignal): Promise<RawResult> {
  return requestRaw('GET', path, undefined, signal);
}

async function requestRaw(method: 'GET' | 'POST', path: string, body?: unknown, signal?: AbortSignal): Promise<RawResult> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res: TransportLike;
  try {
    res = await currentTransport()({ method, path, headers, body: JSON.stringify(body), signal });
  } catch (cause) {
    throw new ApiRequestError({
      status: 0,
      code: 'network_error',
      message: cause instanceof Error ? cause.message : 'Network request failed',
    });
  }
  let parsed: unknown = res.body;
  if (typeof res.body === 'string' && res.body) {
    try {
      parsed = JSON.parse(res.body);
    } catch {
      parsed = res.body;
    }
  }
  return { status: res.status, headers: res.headers, body: parsed };
}

type TransportLike = { status: number; headers: Record<string, string>; body: string };

export const api = {
  get: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'body'>) => request<T>(path, { ...opts, method: 'GET' }),
  post: <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...opts, method: 'POST', body }),
};
