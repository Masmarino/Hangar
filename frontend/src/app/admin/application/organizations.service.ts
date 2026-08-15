import { Injectable, inject } from '@angular/core'
import { Observable, catchError, shareReplay, tap, throwError } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OidcIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'
import { ORGANIZATIONS_PORT } from './organizations.port'

@Injectable({ providedIn: 'root' })
export class OrganizationsService {
  private readonly port = inject(ORGANIZATIONS_PORT)

  private cachedList$: Observable<OrganizationSummary[]> | null = null

  list(options?: { forceRefresh?: boolean }): Observable<OrganizationSummary[]> {
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

  get(id: string): Observable<OrganizationSummary> {
    return this.port.get(id)
  }

  create(slug: string, displayName: string): Observable<OrganizationSummary> {
    return this.port.create(slug, displayName).pipe(tap(() => (this.cachedList$ = null)))
  }

  getIdentityProvider(id: string): Observable<IdentityProviderSummary> {
    return this.port.getIdentityProvider(id)
  }

  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void> {
    return this.port.setLdapIdentityProvider(id, config).pipe(tap(() => (this.cachedList$ = null)))
  }

  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void> {
    return this.port.setOidcIdentityProvider(id, config).pipe(tap(() => (this.cachedList$ = null)))
  }

  clearIdentityProvider(id: string): Observable<void> {
    return this.port.clearIdentityProvider(id).pipe(tap(() => (this.cachedList$ = null)))
  }
}
