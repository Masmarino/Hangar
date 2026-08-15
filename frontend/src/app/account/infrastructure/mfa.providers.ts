import { Provider } from '@angular/core'
import { MFA_PORT } from '../application/mfa.port'
import { HttpMfaAdapter } from './http-mfa.adapter'

export const mfaProviders: Provider[] = [{ provide: MFA_PORT, useClass: HttpMfaAdapter }]
