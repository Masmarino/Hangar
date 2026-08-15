import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { SystemSettings } from '../domain/system-settings.entity'
import { SYSTEM_SETTINGS_PORT } from './system-settings.port'

@Injectable({ providedIn: 'root' })
export class SystemSettingsService {
  private readonly port = inject(SYSTEM_SETTINGS_PORT)

  get(): Observable<SystemSettings> {
    return this.port.get()
  }

  update(settings: SystemSettings): Observable<void> {
    return this.port.update(settings)
  }
}
