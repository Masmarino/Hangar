import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'
import { OrganizationMembersPort } from '../application/organization-members.port'

@Injectable()
export class HttpOrganizationMembersAdapter implements OrganizationMembersPort {
  private readonly http = inject(HttpClient)

  list(organizationId: string): Observable<OrganizationMember[]> {
    return this.http.get<OrganizationMember[]>(`/api/organizations/${organizationId}/users`)
  }

  invite(organizationId: string, username: string, email: string, isOrganizationAdmin: boolean): Observable<OrganizationMember> {
    return this.http.post<OrganizationMember>(`/api/organizations/${organizationId}/users`, {
      username,
      email,
      is_organization_admin: isOrganizationAdmin,
    })
  }

  setOrganizationAdmin(organizationId: string, userId: string, isOrganizationAdmin: boolean): Observable<void> {
    return this.http.put<void>(`/api/organizations/${organizationId}/users/${userId}/organization-admin`, {
      is_organization_admin: isOrganizationAdmin,
    })
  }
}
