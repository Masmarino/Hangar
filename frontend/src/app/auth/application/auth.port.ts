import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import {
  LoginResponse,
  SsoConfig,
  TotpSetupComplete,
  TotpSetupEnrollment,
} from '../domain/auth.types'

/** Everything the application layer needs to reach the backend's auth endpoints — implemented by an infrastructure adapter, never called directly by a component. */
export interface AuthPort {
  login(username: string, password: string): Observable<LoginResponse>
  register(username: string, email: string, password: string): Observable<LoginResponse>
  getSsoConfig(): Observable<SsoConfig>
  loginWithLdap(username: string, password: string): Observable<LoginResponse>
  activate(token: string, newPassword: string): Observable<void>
  verifyMfa(mfaToken: string, code?: string, backupCode?: string): Observable<LoginResponse>
  // The server's JSON-safe WebAuthn options, passed straight through to the browser's
  // credentials API — never inspected here.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  startMfaPasskey(mfaToken: string): Observable<{ challenge_id: string; public_key: any }>
  finishMfaPasskey(
    mfaToken: string,
    challengeId: string,
    credential: unknown,
  ): Observable<LoginResponse>
  startTotpSetup(mfaToken: string): Observable<TotpSetupEnrollment>
  confirmTotpSetup(mfaToken: string, code: string): Observable<TotpSetupComplete>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  startPasskeySetup(mfaToken: string): Observable<{ challenge_id: string; public_key: any }>
  finishPasskeySetup(
    mfaToken: string,
    challengeId: string,
    credential: unknown,
    name: string,
  ): Observable<LoginResponse>
}

export const AUTH_PORT = new InjectionToken<AuthPort>('AuthPort')
