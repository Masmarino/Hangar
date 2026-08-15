import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { ApiToken, CreatedApiToken } from '../domain/api-token.entity'
import { API_TOKEN_PORT } from './api-token.port'

@Injectable({ providedIn: 'root' })
export class ApiTokensApplicationService {
  private readonly port = inject(API_TOKEN_PORT)

  list(): Observable<ApiToken[]> {
    return this.port.list()
  }

  create(label: string): Observable<CreatedApiToken> {
    return this.port.create(label)
  }

  revoke(id: string): Observable<void> {
    return this.port.revoke(id)
  }
}
