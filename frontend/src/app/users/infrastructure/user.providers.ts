import { Provider } from '@angular/core'
import { USER_PORT } from '../application/user.port'
import { HttpUserAdapter } from './http-user.adapter'

export const userProviders: Provider[] = [{ provide: USER_PORT, useClass: HttpUserAdapter }]
