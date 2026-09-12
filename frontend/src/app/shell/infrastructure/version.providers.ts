import { Provider } from '@angular/core'
import { VERSION_PORT } from '../application/version.port'
import { HttpVersionAdapter } from './http-version.adapter'

export const versionProviders: Provider[] = [
  { provide: VERSION_PORT, useClass: HttpVersionAdapter },
]
