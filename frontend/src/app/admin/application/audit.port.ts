import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { AuditEntry, AuditQuery, BlockedAccount } from '../domain/audit.entity'

export interface AuditPort {
  query(filter?: AuditQuery): Observable<AuditEntry[]>
  blockedAccounts(): Observable<BlockedAccount[]>
}

export const AUDIT_PORT = new InjectionToken<AuditPort>('AuditPort')
