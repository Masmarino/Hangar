import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  LoginResponse,
  SsoConfig,
  TotpSetupComplete,
  TotpSetupEnrollment,
} from '../domain/auth.types'
import { AuthPort } from '../application/auth.port'

@Injectable()
export class HttpAuthAdapter implements AuthPort {
  private readonly http = inject(HttpClient)

  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/login', { username, password })
  }

  register(username: string, email: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/register', { username, email, password })
  }

  getSsoConfig(): Observable<SsoConfig> {
    return this.http.get<SsoConfig>('/api/auth/sso/config')
  }

  loginWithLdap(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/sso/ldap', { username, password })
  }

  activate(token: string, newPassword: string): Observable<void> {
    return this.http.post<void>('/api/auth/activate', { token, new_password: newPassword })
  }

  verifyMfa(mfaToken: string, code?: string, backupCode?: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/mfa/verify', {
      mfa_token: mfaToken,
      code,
      backup_code: backupCode,
    })
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  startMfaPasskey(mfaToken: string): Observable<{ challenge_id: string; public_key: any }> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return this.http.post<{ challenge_id: string; public_key: any }>(
      '/api/auth/mfa/passkey/start',
      { mfa_token: mfaToken },
    )
  }

  finishMfaPasskey(
    mfaToken: string,
    challengeId: string,
    credential: unknown,
  ): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/mfa/passkey/finish', {
      mfa_token: mfaToken,
      challenge_id: challengeId,
      credential,
    })
  }

  startTotpSetup(mfaToken: string): Observable<TotpSetupEnrollment> {
    return this.http.post<TotpSetupEnrollment>('/api/auth/mfa/setup/totp/enroll', {
      mfa_token: mfaToken,
    })
  }

  confirmTotpSetup(mfaToken: string, code: string): Observable<TotpSetupComplete> {
    return this.http.post<TotpSetupComplete>('/api/auth/mfa/setup/totp/confirm', {
      mfa_token: mfaToken,
      code,
    })
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  startPasskeySetup(mfaToken: string): Observable<{ challenge_id: string; public_key: any }> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return this.http.post<{ challenge_id: string; public_key: any }>(
      '/api/auth/mfa/setup/passkey/start',
      { mfa_token: mfaToken },
    )
  }

  finishPasskeySetup(
    mfaToken: string,
    challengeId: string,
    credential: unknown,
    name: string,
  ): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/mfa/setup/passkey/finish', {
      mfa_token: mfaToken,
      challenge_id: challengeId,
      credential,
      name,
    })
  }
}
