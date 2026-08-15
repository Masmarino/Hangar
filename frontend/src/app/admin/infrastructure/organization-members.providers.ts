import { Provider } from '@angular/core'
import { ORGANIZATION_MEMBERS_PORT } from '../application/organization-members.port'
import { HttpOrganizationMembersAdapter } from './http-organization-members.adapter'

export const organizationMembersProviders: Provider[] = [
  { provide: ORGANIZATION_MEMBERS_PORT, useClass: HttpOrganizationMembersAdapter },
]
