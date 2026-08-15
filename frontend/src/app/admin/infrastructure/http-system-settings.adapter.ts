import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { SystemSettings } from '../domain/system-settings.entity'
import { SystemSettingsPort } from '../application/system-settings.port'

@Injectable()
export class HttpSystemSettingsAdapter implements SystemSettingsPort {
  private readonly http = inject(HttpClient)

  get(): Observable<SystemSettings> {
    return this.http.get<SystemSettings>('/api/admin/settings')
  }

  update(settings: SystemSettings): Observable<void> {
    return this.http.put<void>('/api/admin/settings', settings)
  }
}
