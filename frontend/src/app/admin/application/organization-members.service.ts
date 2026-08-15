import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'
import { ORGANIZATION_MEMBERS_PORT } from './organization-members.port'

@Injectable({ providedIn: 'root' })
export class OrganizationMembersService {
  private readonly port = inject(ORGANIZATION_MEMBERS_PORT)

  list(organizationId: string): Observable<OrganizationMember[]> {
    return this.port.list(organizationId)
  }

  invite(organizationId: string, username: string, email: string, isOrganizationAdmin: boolean): Observable<OrganizationMember> {
    return this.port.invite(organizationId, username, email, isOrganizationAdmin)
  }

  setOrganizationAdmin(organizationId: string, userId: string, isOrganizationAdmin: boolean): Observable<void> {
    return this.port.setOrganizationAdmin(organizationId, userId, isOrganizationAdmin)
  }
}
