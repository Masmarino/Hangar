import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OidcIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'
import { OrganizationsPort } from '../application/organizations.port'

@Injectable()
export class HttpOrganizationsAdapter implements OrganizationsPort {
  private readonly http = inject(HttpClient)

  list(): Observable<OrganizationSummary[]> {
    return this.http.get<OrganizationSummary[]>('/api/organizations')
  }

  get(id: string): Observable<OrganizationSummary> {
    return this.http.get<OrganizationSummary>(`/api/organizations/${id}`)
  }

  create(slug: string, displayName: string): Observable<OrganizationSummary> {
    return this.http.post<OrganizationSummary>('/api/organizations', {
      slug,
      display_name: displayName,
    })
  }

  getIdentityProvider(id: string): Observable<IdentityProviderSummary> {
    return this.http.get<IdentityProviderSummary>(`/api/organizations/${id}/identity-provider`)
  }

  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void> {
    return this.http.put<void>(`/api/organizations/${id}/identity-provider`, {
      type: 'ldap',
      ...config,
    })
  }

  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void> {
    return this.http.put<void>(`/api/organizations/${id}/identity-provider`, {
      type: 'oidc',
      ...config,
    })
  }

  clearIdentityProvider(id: string): Observable<void> {
    return this.http.delete<void>(`/api/organizations/${id}/identity-provider`)
  }
}
