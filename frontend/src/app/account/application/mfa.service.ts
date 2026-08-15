import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import {
  BackupCodes,
  MfaStatus,
  PasskeyRegistrationStart,
  PasskeySummary,
  TotpEnrollment,
} from '../domain/mfa.types'
import { MFA_PORT } from './mfa.port'

@Injectable({ providedIn: 'root' })
export class MfaService {
  private readonly port = inject(MFA_PORT)

  getStatus(): Observable<MfaStatus> {
    return this.port.getStatus()
  }

  enrollTotp(): Observable<TotpEnrollment> {
    return this.port.enrollTotp()
  }

  confirmTotp(code: string): Observable<BackupCodes> {
    return this.port.confirmTotp(code)
  }

  disableTotp(currentPassword: string): Observable<void> {
    return this.port.disableTotp(currentPassword)
  }

  regenerateBackupCodes(currentPassword: string): Observable<BackupCodes> {
    return this.port.regenerateBackupCodes(currentPassword)
  }

  listPasskeys(): Observable<PasskeySummary[]> {
    return this.port.listPasskeys()
  }

  startPasskeyRegistration(): Observable<PasskeyRegistrationStart> {
    return this.port.startPasskeyRegistration()
  }

  finishPasskeyRegistration(
    challengeId: string,
    credential: unknown,
    name: string,
  ): Observable<void> {
    return this.port.finishPasskeyRegistration(challengeId, credential, name)
  }

  deletePasskey(id: string, currentPassword: string): Observable<void> {
    return this.port.deletePasskey(id, currentPassword)
  }
}
