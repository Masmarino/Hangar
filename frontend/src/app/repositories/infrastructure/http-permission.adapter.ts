import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { PermissionEntry, Role, UserLookup, UserPermissionEntry } from '../domain/permission.entity'
import { PermissionPort } from '../application/permission.port'

@Injectable()
export class HttpPermissionAdapter implements PermissionPort {
  private readonly http = inject(HttpClient)

  list(repositoryId: string): Observable<PermissionEntry[]> {
    return this.http.get<PermissionEntry[]>(`/api/repositories/${repositoryId}/permissions`)
  }

  lookupUser(username: string): Observable<UserLookup> {
    return this.http.get<UserLookup>('/api/users/lookup', { params: { username } })
  }

  searchUsers(query: string): Observable<UserLookup[]> {
    return this.http.get<UserLookup[]>('/api/users/search', { params: { q: query } })
  }

  grant(repositoryId: string, userId: string, role: Role): Observable<void> {
    return this.http.put<void>(`/api/repositories/${repositoryId}/permissions/${userId}`, { role })
  }

  revoke(repositoryId: string, userId: string): Observable<void> {
    return this.http.delete<void>(`/api/repositories/${repositoryId}/permissions/${userId}`)
  }

  listForUser(userId: string): Observable<UserPermissionEntry[]> {
    return this.http.get<UserPermissionEntry[]>(`/api/users/${userId}/permissions`)
  }
}
