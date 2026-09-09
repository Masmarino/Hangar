import { TestBed } from '@angular/core/testing'
import { provideHttpClient } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import {
  ActivatedRouteSnapshot,
  convertToParamMap,
  provideRouter,
  Router,
  UrlTree,
} from '@angular/router'
import { Observable, firstValueFrom, of, throwError } from 'rxjs'
import { organizationAdminGuard } from './organization-admin.guard'
import { ME_PORT, MePort } from '../shell/application/me.port'
import { authProviders } from './infrastructure/auth.providers'

describe('organizationAdminGuard', () => {
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

  function runGuard(routeOrgId: string): Promise<boolean | UrlTree> {
    const route = { paramMap: convertToParamMap({ id: routeOrgId }) } as ActivatedRouteSnapshot
    const result$ = TestBed.runInInjectionContext(() =>
      organizationAdminGuard(route, {} as never),
    ) as Observable<boolean | UrlTree>
    return firstValueFrom(result$)
  }

  it('allows a super-admin to access any organization', async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'admin',
          is_super_admin: true,
          is_organization_admin: false,
          organization_id: 'org-other',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })

    expect(await runGuard('org-1')).toBe(true)
  })

  it("allows an org-admin to access their own organization's page", async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'org-admin',
          is_super_admin: false,
          is_organization_admin: true,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })

    expect(await runGuard('org-1')).toBe(true)
  })

  it("redirects an org-admin trying to access a DIFFERENT organization's page", async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'org-admin',
          is_super_admin: false,
          is_organization_admin: true,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-2')).toEqual(router.createUrlTree(['/repositories']))
  })

  it('redirects a regular member, even of the target organization', async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'regular',
          is_super_admin: false,
          is_organization_admin: false,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-1')).toEqual(router.createUrlTree(['/repositories']))
  })

  it('fails toward redirect, rather than hanging navigation, when the identity request errors', async () => {
    setup({ load: () => throwError(() => new Error('network blip')) })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-1')).toEqual(router.createUrlTree(['/repositories']))
  })
})
