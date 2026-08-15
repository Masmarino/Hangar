import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { AdminApiToken } from '../domain/admin-api-token.entity'
import { ADMIN_API_TOKEN_PORT } from './admin-api-token.port'

@Injectable({ providedIn: 'root' })
export class AdminApiTokensService {
  private readonly port = inject(ADMIN_API_TOKEN_PORT)

  list(): Observable<AdminApiToken[]> {
    return this.port.list()
  }

  revoke(id: string): Observable<void> {
    return this.port.revoke(id)
  }
}
