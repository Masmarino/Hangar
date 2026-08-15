import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OidcIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'

/** Everything the application layer needs from wherever organizations actually live — implemented by an infrastructure adapter, never called directly by a component. */
export interface OrganizationsPort {
  list(): Observable<OrganizationSummary[]>
  get(id: string): Observable<OrganizationSummary>
  create(slug: string, displayName: string): Observable<OrganizationSummary>
  getIdentityProvider(id: string): Observable<IdentityProviderSummary>
  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void>
  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void>
  clearIdentityProvider(id: string): Observable<void>
}

export const ORGANIZATIONS_PORT = new InjectionToken<OrganizationsPort>('OrganizationsPort')
