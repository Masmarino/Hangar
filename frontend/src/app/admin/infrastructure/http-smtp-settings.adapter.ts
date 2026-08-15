import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'
import { SmtpSettingsPort } from '../application/smtp-settings.port'

@Injectable()
export class HttpSmtpSettingsAdapter implements SmtpSettingsPort {
  private readonly http = inject(HttpClient)

  get(): Observable<SmtpSettings | null> {
    return this.http.get<SmtpSettings | null>('/api/admin/settings/smtp')
  }

  update(settings: UpdateSmtpSettings): Observable<void> {
    return this.http.put<void>('/api/admin/settings/smtp', settings)
  }

  sendTestEmail(to: string): Observable<void> {
    return this.http.post<void>('/api/admin/settings/smtp/test', { to })
  }
}
