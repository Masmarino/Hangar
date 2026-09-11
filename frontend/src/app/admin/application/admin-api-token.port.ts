import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { AdminApiToken } from '../domain/admin-api-token.entity'

export interface AdminApiTokenPort {
  list(organizationId?: string): Observable<AdminApiToken[]>
  revoke(id: string): Observable<void>
}

export const ADMIN_API_TOKEN_PORT = new InjectionToken<AdminApiTokenPort>('AdminApiTokenPort')
