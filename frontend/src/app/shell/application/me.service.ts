import { Injectable, effect, inject, signal } from '@angular/core'
import { Observable, catchError, shareReplay, tap, throwError } from 'rxjs'
import { AuthService } from '../../auth/application/auth.service'
import { MeResponse } from '../domain/me.entity'
import { ME_PORT } from './me.port'

@Injectable({ providedIn: 'root' })
export class MeService {
  private readonly port = inject(ME_PORT)
  private readonly auth = inject(AuthService)

  readonly username = signal<string | null>(null)
  readonly isSuperAdmin = signal(false)
  readonly createdAt = signal<string | null>(null)
  readonly organizationId = signal<string | null>(null)
  readonly isOrganizationAdmin = signal(false)

  private cached$: Observable<MeResponse> | null = null

  constructor() {
    // Skip the effect's first run, or we'd wipe out state a caller just set on inject.
    let previousToken = this.auth.token()
    effect(() => {
      const token = this.auth.token()
      if (token === previousToken) {
        return
      }
      previousToken = token
      this.cached$ = null
      this.username.set(null)
      this.isSuperAdmin.set(false)
      this.createdAt.set(null)
      this.organizationId.set(null)
      this.isOrganizationAdmin.set(false)
    })
  }

  /** Cached per token: multiple callers (the shell, route guards) share one request. */
  load(options?: { forceRefresh?: boolean }): Observable<MeResponse> {
    if (!this.cached$ || options?.forceRefresh) {
      this.cached$ = this.port.load().pipe(
        tap((me) => {
          this.username.set(me.username)
          this.isSuperAdmin.set(me.is_super_admin)
          this.createdAt.set(me.created_at)
          this.organizationId.set(me.organization_id)
          this.isOrganizationAdmin.set(me.is_organization_admin)
        }),
        // Never cache a failure — a transient error must not permanently strand the user.
        catchError((err: unknown) => {
          this.cached$ = null
          return throwError(() => err)
        }),
        shareReplay(1),
      )
    }
    return this.cached$
  }

  changePassword(currentPassword: string, newPassword: string): Observable<void> {
    return this.port.changePassword(currentPassword, newPassword)
  }
}
