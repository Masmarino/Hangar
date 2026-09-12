import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { VersionResponse } from '../domain/version.entity'

/** The running server's own version — implemented by an infrastructure adapter, never called directly by a component. */
export interface VersionPort {
  load(): Observable<VersionResponse>
}

export const VERSION_PORT = new InjectionToken<VersionPort>('VersionPort')
