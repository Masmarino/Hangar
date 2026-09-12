import { ApplicationConfig, LOCALE_ID, provideZonelessChangeDetection } from '@angular/core'
import { provideRouter } from '@angular/router'
import { provideHttpClient, withInterceptors } from '@angular/common/http'
import { provideTransloco } from '@jsverse/transloco'

import { routes } from './app.routes'
import { authInterceptor } from './auth/auth.interceptor'
import { TranslocoHttpLoader } from './transloco-loader'
import { registerLocaleData } from '@angular/common'
import localeFr from '@angular/common/locales/fr'
import { apiTokenProviders } from './tokens/infrastructure/api-token.providers'
import { authProviders } from './auth/infrastructure/auth.providers'
import { mfaProviders } from './account/infrastructure/mfa.providers'
import { userProviders } from './users/infrastructure/user.providers'
import { repositoryProviders } from './repositories/infrastructure/repository.providers'
import { adminProviders } from './admin/infrastructure/admin.providers'
import { meProviders } from './shell/infrastructure/me.providers'
import { versionProviders } from './shell/infrastructure/version.providers'
import { organizationsProviders } from './admin/infrastructure/organizations.providers'
import { organizationMembersProviders } from './admin/infrastructure/organization-members.providers'
import { provideHangarIcons } from './shared/register-icons'
registerLocaleData(localeFr)

export const appConfig: ApplicationConfig = {
  providers: [
    provideZonelessChangeDetection(),
    provideHangarIcons(),
    provideRouter(routes),
    provideHttpClient(withInterceptors([authInterceptor])),
    {
      provide: LOCALE_ID,
      useValue: 'fr-FR',
    },
    // Foundation for future i18n — not wired into any component yet, every string is
    // still a hardcoded French literal.
    provideTransloco({
      config: {
        availableLangs: ['fr'],
        defaultLang: 'fr',
        reRenderOnLangChange: true,
        prodMode: false,
      },
      loader: TranslocoHttpLoader,
    }),
    // Feature port -> adapter bindings (hexagonal architecture) — each
    // feature owns its own providers array; this just spreads them in.
    ...apiTokenProviders,
    ...authProviders,
    ...mfaProviders,
    ...userProviders,
    ...organizationsProviders,
    ...organizationMembersProviders,
    ...repositoryProviders,
    ...adminProviders,
    ...meProviders,
    ...versionProviders,
  ],
}
