import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { PermissionEntry, Role, UserLookup, UserPermissionEntry } from '../domain/permission.entity'
import { PERMISSION_PORT } from './permission.port'

@Injectable({ providedIn: 'root' })
export class PermissionsService {
  private readonly port = inject(PERMISSION_PORT)

  list(repositoryId: string): Observable<PermissionEntry[]> {
    return this.port.list(repositoryId)
  }

  lookupUser(username: string): Observable<UserLookup> {
    return this.port.lookupUser(username)
  }

  searchUsers(query: string): Observable<UserLookup[]> {
    return this.port.searchUsers(query)
  }

  grant(repositoryId: string, userId: string, role: Role): Observable<void> {
    return this.port.grant(repositoryId, userId, role)
  }

  revoke(repositoryId: string, userId: string): Observable<void> {
    return this.port.revoke(repositoryId, userId)
  }

  listForUser(userId: string): Observable<UserPermissionEntry[]> {
    return this.port.listForUser(userId)
  }
}
