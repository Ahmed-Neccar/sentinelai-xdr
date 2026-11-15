/**
 * The one place that talks to the server.
 *
 * Components never call `fetch` themselves: they use `api()` (or a typed adapter in this folder
 * that wraps it). That keeps the access token, the silent renewal after a 401, the "session has
 * ended" signal and the error text in one module, so a security change on the server is one
 * change here and not a hunt through the screens.
 */

export const API = '/api/v1'
export const SENSOR_CONTROL = 'http://127.0.0.1:8765'

let accessToken = ''
let language: 'en' | 'tr' = 'en'
// Called when the server will no longer renew the session (it ended, was revoked or hit its time limit).
let sessionLost: () => void = () => {}

export const getAccessToken = () => accessToken
export const setAccessToken = (token: string) => { accessToken = token }
export const setHttpLanguage = (value: 'en' | 'tr') => { language = value }
export const setSessionLostHandler = (handler: () => void) => { sessionLost = handler }

/** Talks to the local Windows sensor controller (a program on this computer, not the server). */
export async function sensorControl<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${SENSOR_CONTROL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init.headers },
    cache: 'no-store',
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw Error(body?.error || 'The Windows sensor controller could not complete this request.')
  return body as T
}

function failureMessage(status: number, body: any): string {
  const fields = body?.error?.details?.fields as { location: string; message: string }[] | undefined
  const detail = fields?.map(f => `${f.location}: ${f.message}`).join('; ')
  const statusMessage = status === 502
    ? (language === 'tr'
      ? 'Giriş servisine ulaşılamıyor (502). Uygulama sunucusunu başlatıp yeniden deneyin.'
      : 'The sign-in service is unavailable (502). Start the application server and try again.')
    : null
  return [body?.error?.message || statusMessage || `Request failed (${status})`, detail].filter(Boolean).join(' — ')
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  let res = await fetch(API + path, { ...init, headers, credentials: 'include' })
  if (res.status === 401 && !['/auth/login', '/auth/refresh'].includes(path)) {
    const renewal = await fetch(API + '/auth/refresh', { method: 'POST', credentials: 'include' })
    if (renewal.ok) {
      accessToken = (await renewal.json()).access_token
      headers.set('Authorization', `Bearer ${accessToken}`)
      res = await fetch(API + path, { ...init, headers, credentials: 'include' })
    } else sessionLost()
  }
  if (!res.ok) throw Error(failureMessage(res.status, await res.json().catch(() => ({}))))
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

/** Download a file the server builds (for example a CSV report) with the current session. */
export async function download(path: string): Promise<Blob> {
  const res = await fetch(API + path, { headers: { Authorization: `Bearer ${accessToken}` }, credentials: 'include' })
  if (!res.ok) throw Error('Download failed')
  return res.blob()
}
