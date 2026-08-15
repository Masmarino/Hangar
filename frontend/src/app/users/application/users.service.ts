import { Injectable, inject } from '@angular/core'
import { Observable, catchError, shareReplay, tap, throwError } from 'rxjs'
import { UserSummary } from '../domain/user.entity'
import { USER_PORT } from './user.port'

@Injectable({ providedIn: 'root' })
export class UsersService {
  private readonly port = inject(USER_PORT)

  private cachedList$: Observable<UserSummary[]> | null = null

  // cached across callers, cleared by any mutation below — forceRefresh is for the shell's
  // search, which needs to see writes that could've come from another tab
  list(options?: { forceRefresh?: boolean }): Observable<UserSummary[]> {
    if (!this.cachedList$ || options?.forceRefresh) {
      this.cachedList$ = this.port.list().pipe(
        catchError((err: unknown) => {
          this.cachedList$ = null
          return throwError(() => err)
        }),
        shareReplay(1),
      )
    }
    return this.cachedList$
  }

  get(id: string): Observable<UserSummary> {
    return this.port.get(id)
  }

  create(username: string, email: string, isSuperAdmin: boolean): Observable<UserSummary> {
    return this.port
      .create(username, email, isSuperAdmin)
      .pipe(tap(() => (this.cachedList$ = null)))
  }

  delete(id: string): Observable<void> {
    return this.port.delete(id).pipe(tap(() => (this.cachedList$ = null)))
  }

  setSuperAdmin(id: string, isSuperAdmin: boolean): Observable<void> {
    return this.port.setSuperAdmin(id, isSuperAdmin).pipe(tap(() => (this.cachedList$ = null)))
  }

  resendInvitation(id: string): Observable<void> {
    return this.port.resendInvitation(id)
  }
}
