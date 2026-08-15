import { Provider } from '@angular/core'
import { ORGANIZATIONS_PORT } from '../application/organizations.port'
import { HttpOrganizationsAdapter } from './http-organizations.adapter'

export const organizationsProviders: Provider[] = [
  { provide: ORGANIZATIONS_PORT, useClass: HttpOrganizationsAdapter },
]
