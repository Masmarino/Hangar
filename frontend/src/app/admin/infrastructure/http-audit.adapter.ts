import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { AuditEntry, AuditQuery, BlockedAccount } from '../domain/audit.entity'
import { AuditPort } from '../application/audit.port'

@Injectable()
export class HttpAuditAdapter implements AuditPort {
  private readonly http = inject(HttpClient)

  query(filter: AuditQuery = {}): Observable<AuditEntry[]> {
    const params: Record<string, string> = {}
    for (const [key, value] of Object.entries(filter)) {
      if (value) {
        params[key] = value
      }
    }
    return this.http.get<AuditEntry[]>('/api/audit/events', { params })
  }

  blockedAccounts(): Observable<BlockedAccount[]> {
    return this.http.get<BlockedAccount[]>('/api/admin/security/blocked')
  }
}
