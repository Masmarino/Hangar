import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'
import { SmtpSettingsPort } from '../application/smtp-settings.port'

function orgParams(organizationId?: string): Record<string, string> {
  return organizationId ? { organization_id: organizationId } : {}
}

@Injectable()
export class HttpSmtpSettingsAdapter implements SmtpSettingsPort {
  private readonly http = inject(HttpClient)

  get(organizationId?: string): Observable<SmtpSettings | null> {
    return this.http.get<SmtpSettings | null>('/api/admin/settings/smtp', {
      params: orgParams(organizationId),
    })
  }

  update(settings: UpdateSmtpSettings, organizationId?: string): Observable<void> {
    return this.http.put<void>('/api/admin/settings/smtp', settings, {
      params: orgParams(organizationId),
    })
  }

  sendTestEmail(to: string, organizationId?: string): Observable<void> {
    return this.http.post<void>(
      '/api/admin/settings/smtp/test',
      { to },
      { params: orgParams(organizationId) },
    )
  }
}
