import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { AdminApiToken } from '../domain/admin-api-token.entity'
import { AdminApiTokenPort } from '../application/admin-api-token.port'

@Injectable()
export class HttpAdminApiTokenAdapter implements AdminApiTokenPort {
  private readonly http = inject(HttpClient)

  list(): Observable<AdminApiToken[]> {
    return this.http.get<AdminApiToken[]>('/api/admin/tokens')
  }

  revoke(id: string): Observable<void> {
    return this.http.delete<void>(`/api/admin/tokens/${id}`)
  }
}
