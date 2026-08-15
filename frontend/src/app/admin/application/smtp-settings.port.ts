import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'

export interface SmtpSettingsPort {
  get(): Observable<SmtpSettings | null>
  update(settings: UpdateSmtpSettings): Observable<void>
  sendTestEmail(to: string): Observable<void>
}

export const SMTP_SETTINGS_PORT = new InjectionToken<SmtpSettingsPort>('SmtpSettingsPort')
