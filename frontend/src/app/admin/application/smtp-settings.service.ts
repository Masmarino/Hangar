import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'
import { SMTP_SETTINGS_PORT } from './smtp-settings.port'

@Injectable({ providedIn: 'root' })
export class SmtpSettingsService {
  private readonly port = inject(SMTP_SETTINGS_PORT)

  get(organizationId?: string): Observable<SmtpSettings | null> {
    return this.port.get(organizationId)
  }

  update(settings: UpdateSmtpSettings, organizationId?: string): Observable<void> {
    return this.port.update(settings, organizationId)
  }

  sendTestEmail(to: string, organizationId?: string): Observable<void> {
    return this.port.sendTestEmail(to, organizationId)
  }
}
