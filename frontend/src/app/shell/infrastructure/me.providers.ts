import { Provider } from '@angular/core'
import { ME_PORT } from '../application/me.port'
import { HttpMeAdapter } from './http-me.adapter'

export const meProviders: Provider[] = [{ provide: ME_PORT, useClass: HttpMeAdapter }]
