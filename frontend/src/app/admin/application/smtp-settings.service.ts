import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { SmtpSettings, UpdateSmtpSettings } from '../domain/smtp-settings.entity'
import { SMTP_SETTINGS_PORT } from './smtp-settings.port'

@Injectable({ providedIn: 'root' })
export class SmtpSettingsService {
  private readonly port = inject(SMTP_SETTINGS_PORT)

  get(): Observable<SmtpSettings | null> {
    return this.port.get()
  }

  update(settings: UpdateSmtpSettings): Observable<void> {
    return this.port.update(settings)
  }

  sendTestEmail(to: string): Observable<void> {
    return this.port.sendTestEmail(to)
  }
}
