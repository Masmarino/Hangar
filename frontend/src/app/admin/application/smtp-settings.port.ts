import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'

export interface SmtpSettingsPort {
  get(organizationId?: string): Observable<SmtpSettings | null>
  update(settings: UpdateSmtpSettings, organizationId?: string): Observable<void>
  sendTestEmail(to: string, organizationId?: string): Observable<void>
}

export const SMTP_SETTINGS_PORT = new InjectionToken<SmtpSettingsPort>('SmtpSettingsPort')
