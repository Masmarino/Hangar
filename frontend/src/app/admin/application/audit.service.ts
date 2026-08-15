import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { AuditEntry, AuditQuery, BlockedAccount } from '../domain/audit.entity'
import { AUDIT_PORT } from './audit.port'

@Injectable({ providedIn: 'root' })
export class AuditService {
  private readonly port = inject(AUDIT_PORT)

  query(filter: AuditQuery = {}): Observable<AuditEntry[]> {
    return this.port.query(filter)
  }

  blockedAccounts(): Observable<BlockedAccount[]> {
    return this.port.blockedAccounts()
  }
}
