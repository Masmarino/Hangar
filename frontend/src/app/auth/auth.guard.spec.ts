import { TestBed } from '@angular/core/testing'
import { provideRouter, Router } from '@angular/router'
import { provideHttpClient } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { authGuard } from './auth.guard'
import { AuthService } from './application/auth.service'
import { authProviders } from './infrastructure/auth.providers'

describe('authGuard', () => {
  it('allows navigation when authenticated', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...authProviders,
      ],
    })
    const auth = TestBed.inject(AuthService)
    auth.token.set('a-jwt-token')

    const result = TestBed.runInInjectionContext(() => authGuard({} as never, {} as never))

    expect(result).toBe(true)
  })

  it('redirects to /login when not authenticated', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...authProviders,
      ],
    })
    const router = TestBed.inject(Router)

    const result = TestBed.runInInjectionContext(() => authGuard({} as never, {} as never))

    expect(result).toEqual(router.createUrlTree(['/login']))
  })
})
