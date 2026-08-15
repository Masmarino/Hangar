import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  BackupCodes,
  MfaStatus,
  PasskeyRegistrationStart,
  PasskeySummary,
  TotpEnrollment,
} from '../domain/mfa.types'
import { MfaPort } from '../application/mfa.port'

@Injectable()
export class HttpMfaAdapter implements MfaPort {
  private readonly http = inject(HttpClient)

  getStatus(): Observable<MfaStatus> {
    return this.http.get<MfaStatus>('/api/me/mfa')
  }

  enrollTotp(): Observable<TotpEnrollment> {
    return this.http.post<TotpEnrollment>('/api/me/mfa/totp/enroll', {})
  }

  confirmTotp(code: string): Observable<BackupCodes> {
    return this.http.post<BackupCodes>('/api/me/mfa/totp/confirm', { code })
  }

  disableTotp(currentPassword: string): Observable<void> {
    return this.http.delete<void>('/api/me/mfa/totp', {
      body: { current_password: currentPassword },
    })
  }

  regenerateBackupCodes(currentPassword: string): Observable<BackupCodes> {
    return this.http.post<BackupCodes>('/api/me/mfa/backup-codes/regenerate', {
      current_password: currentPassword,
    })
  }

  listPasskeys(): Observable<PasskeySummary[]> {
    return this.http.get<PasskeySummary[]>('/api/me/mfa/passkey')
  }

  startPasskeyRegistration(): Observable<PasskeyRegistrationStart> {
    return this.http.post<PasskeyRegistrationStart>('/api/me/mfa/passkey/register/start', {})
  }

  finishPasskeyRegistration(
    challengeId: string,
    credential: unknown,
    name: string,
  ): Observable<void> {
    return this.http.post<void>('/api/me/mfa/passkey/register/finish', {
      challenge_id: challengeId,
      credential,
      name,
    })
  }

  deletePasskey(id: string, currentPassword: string): Observable<void> {
    return this.http.delete<void>(`/api/me/mfa/passkey/${id}`, {
      body: { current_password: currentPassword },
    })
  }
}
