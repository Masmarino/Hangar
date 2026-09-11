import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { SystemSettings } from '../domain/system-settings.entity'

export interface SystemSettingsPort {
  get(organizationId?: string): Observable<SystemSettings>
  update(settings: SystemSettings, organizationId?: string): Observable<void>
}

export const SYSTEM_SETTINGS_PORT = new InjectionToken<SystemSettingsPort>('SystemSettingsPort')
