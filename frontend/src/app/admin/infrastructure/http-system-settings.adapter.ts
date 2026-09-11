import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { SystemSettings } from '../domain/system-settings.entity'
import { SystemSettingsPort } from '../application/system-settings.port'

function orgParams(organizationId?: string): Record<string, string> {
  return organizationId ? { organization_id: organizationId } : {}
}

@Injectable()
export class HttpSystemSettingsAdapter implements SystemSettingsPort {
  private readonly http = inject(HttpClient)

  get(organizationId?: string): Observable<SystemSettings> {
    return this.http.get<SystemSettings>('/api/admin/settings', {
      params: orgParams(organizationId),
    })
  }

  update(settings: SystemSettings, organizationId?: string): Observable<void> {
    return this.http.put<void>('/api/admin/settings', settings, {
      params: orgParams(organizationId),
    })
  }
}
