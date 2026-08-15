import { Provider } from '@angular/core'
import { API_TOKEN_PORT } from '../application/api-token.port'
import { HttpApiTokenAdapter } from './http-api-token.adapter'

export const apiTokenProviders: Provider[] = [
  { provide: API_TOKEN_PORT, useClass: HttpApiTokenAdapter },
]
