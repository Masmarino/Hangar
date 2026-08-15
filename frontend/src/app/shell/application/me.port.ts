import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { MeResponse } from '../domain/me.entity'

/** Everything the application layer needs to reach the current user's own account endpoints — implemented by an infrastructure adapter, never called directly by a component. */
export interface MePort {
  load(): Observable<MeResponse>
  changePassword(currentPassword: string, newPassword: string): Observable<void>
}

export const ME_PORT = new InjectionToken<MePort>('MePort')
