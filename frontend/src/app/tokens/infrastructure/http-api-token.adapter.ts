import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { ApiToken, CreatedApiToken } from '../domain/api-token.entity'
import { ApiTokenPort } from '../application/api-token.port'

@Injectable()
export class HttpApiTokenAdapter implements ApiTokenPort {
  private readonly http = inject(HttpClient)

  list(): Observable<ApiToken[]> {
    return this.http.get<ApiToken[]>('/api/tokens')
  }

  create(label: string): Observable<CreatedApiToken> {
    return this.http.post<CreatedApiToken>('/api/tokens', { label })
  }

  revoke(id: string): Observable<void> {
    return this.http.delete<void>(`/api/tokens/${id}`)
  }
}
