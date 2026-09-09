import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'

/** Everything the application layer needs to manage one organization's members — implemented by an infrastructure adapter, never called directly by a component. */
export interface OrganizationMembersPort {
  list(organizationId: string): Observable<OrganizationMember[]>
  invite(
    organizationId: string,
    username: string,
    email: string,
    isOrganizationAdmin: boolean,
  ): Observable<OrganizationMember>
  setOrganizationAdmin(
    organizationId: string,
    userId: string,
    isOrganizationAdmin: boolean,
  ): Observable<void>
}

export const ORGANIZATION_MEMBERS_PORT = new InjectionToken<OrganizationMembersPort>(
  'OrganizationMembersPort',
)
