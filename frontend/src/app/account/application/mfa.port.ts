import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import {
  BackupCodes,
  MfaStatus,
  PasskeyRegistrationStart,
  PasskeySummary,
  TotpEnrollment,
} from '../domain/mfa.types'

/** Everything the application layer needs to reach the backend's MFA endpoints — implemented by an infrastructure adapter, never called directly by a component. */
export interface MfaPort {
  getStatus(): Observable<MfaStatus>
  enrollTotp(): Observable<TotpEnrollment>
  confirmTotp(code: string): Observable<BackupCodes>
  disableTotp(currentPassword: string): Observable<void>
  regenerateBackupCodes(currentPassword: string): Observable<BackupCodes>
  listPasskeys(): Observable<PasskeySummary[]>
  startPasskeyRegistration(): Observable<PasskeyRegistrationStart>
  finishPasskeyRegistration(
    challengeId: string,
    credential: unknown,
    name: string,
  ): Observable<void>
  deletePasskey(id: string, currentPassword: string): Observable<void>
}

export const MFA_PORT = new InjectionToken<MfaPort>('MfaPort')
