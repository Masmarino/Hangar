import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { UserSummary } from '../domain/user.entity'

/** Everything the application layer needs from wherever users actually live — implemented by an infrastructure adapter, never called directly by a component. */
export interface UserPort {
  list(): Observable<UserSummary[]>
  get(id: string): Observable<UserSummary>
  create(username: string, email: string, isSuperAdmin: boolean): Observable<UserSummary>
  delete(id: string): Observable<void>
  setSuperAdmin(id: string, isSuperAdmin: boolean): Observable<void>
  resendInvitation(id: string): Observable<void>
}

export const USER_PORT = new InjectionToken<UserPort>('UserPort')
