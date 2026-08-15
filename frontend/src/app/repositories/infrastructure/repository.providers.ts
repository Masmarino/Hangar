import { Provider } from '@angular/core'
import { REPOSITORY_PORT } from '../application/repository.port'
import { HttpRepositoryAdapter } from './http-repository.adapter'
import { PERMISSION_PORT } from '../application/permission.port'
import { HttpPermissionAdapter } from './http-permission.adapter'

export const repositoryProviders: Provider[] = [
  { provide: REPOSITORY_PORT, useClass: HttpRepositoryAdapter },
  { provide: PERMISSION_PORT, useClass: HttpPermissionAdapter },
]
