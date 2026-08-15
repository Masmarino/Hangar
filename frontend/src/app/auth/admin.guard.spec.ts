import { TestBed } from '@angular/core/testing'
import { provideHttpClient } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { provideRouter, Router, UrlTree } from '@angular/router'
import { Observable, firstValueFrom, of, throwError } from 'rxjs'
import { adminGuard } from './admin.guard'
import { ME_PORT, MePort } from '../shell/application/me.port'
import { authProviders } from './infrastructure/auth.providers'

describe('adminGuard', () => {
  function setup(port: Partial<MePort>) {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...authProviders,
        { provide: ME_PORT, useValue: port },
      ],
    })
  }

  function runGuard(): Promise<boolean | UrlTree> {
    const result$ = TestBed.runInInjectionContext(() =>
      adminGuard({} as never, {} as never),
    ) as Observable<boolean | UrlTree>
    return firstValueFrom(result$)
  }

  it('allows navigation for a super admin', async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'admin',
          is_super_admin: true,
          is_organization_admin: false,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })

    expect(await runGuard()).toBe(true)
  })

  it('redirects a non-admin to /repositories, even when authenticated', async () => {
    setup({
      load: () =>
        of({
          id: 'user-2',
          username: 'regular',
          is_super_admin: false,
          is_organization_admin: false,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard()).toEqual(router.createUrlTree(['/repositories']))
  })

  it('fails toward non-admin, rather than hanging navigation, when the identity request errors', async () => {
    setup({ load: () => throwError(() => new Error('network blip')) })
    const router = TestBed.inject(Router)

    expect(await runGuard()).toEqual(router.createUrlTree(['/repositories']))
  })

  it('re-checks admin status on every navigation instead of trusting a cached value from before a demotion', async () => {
    let isSuperAdmin = true
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'admin',
          is_super_admin: isSuperAdmin,
          is_organization_admin: false,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard()).toBe(true)

    isSuperAdmin = false
    expect(await runGuard()).toEqual(router.createUrlTree(['/repositories']))
  })
})
