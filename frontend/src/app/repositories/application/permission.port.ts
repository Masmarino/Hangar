import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { PermissionEntry, Role, UserLookup, UserPermissionEntry } from '../domain/permission.entity'

/** Everything the application layer needs from wherever permissions actually live — implemented by an infrastructure adapter, never called directly by a component. */
export interface PermissionPort {
  list(repositoryId: string): Observable<PermissionEntry[]>
  lookupUser(username: string): Observable<UserLookup>
  /** Typeahead search for the permissions-grant form — matches on a username substring. */
  searchUsers(query: string): Observable<UserLookup[]>
  grant(repositoryId: string, userId: string, role: Role): Observable<void>
  revoke(repositoryId: string, userId: string): Observable<void>
  listForUser(userId: string): Observable<UserPermissionEntry[]>
}

export const PERMISSION_PORT = new InjectionToken<PermissionPort>('PermissionPort')
