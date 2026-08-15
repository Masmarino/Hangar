import { Provider } from '@angular/core'
import { AUTH_PORT } from '../application/auth.port'
import { HttpAuthAdapter } from './http-auth.adapter'

export const authProviders: Provider[] = [{ provide: AUTH_PORT, useClass: HttpAuthAdapter }]
