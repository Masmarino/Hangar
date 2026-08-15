import { TestBed } from '@angular/core/testing'
import { provideRouter, Router } from '@angular/router'
import { provideHttpClient, withInterceptors, HttpClient } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { authInterceptor } from './auth.interceptor'
import { AuthService } from './application/auth.service'
import { authProviders } from './infrastructure/auth.providers'

function configure() {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(withInterceptors([authInterceptor])),
      provideHttpClientTesting(),
      provideRouter([]),
      ...authProviders,
    ],
  })
}

describe('authInterceptor', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('attaches the bearer token when one is stored', () => {
    configure()
    TestBed.inject(AuthService).token.set('a-jwt-token')
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    http.get('/api/repositories').subscribe()

    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.headers.get('Authorization')).toBe('Bearer a-jwt-token')
    req.flush([])
  })

  it('clears the token and navigates to /login on a 401 from a non-login endpoint', () => {
    configure()
    const auth = TestBed.inject(AuthService)
    auth.token.set('an-expired-token')
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl')
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    let failed = false
    http.get('/api/repositories').subscribe({ error: () => (failed = true) })

    httpMock
      .expectOne('/api/repositories')
      .flush('Unauthorized', { status: 401, statusText: 'Unauthorized' })

    expect(auth.token()).toBeNull()
    expect(router.navigateByUrl).toHaveBeenCalledWith('/login')
    // The error still reaches the caller so local handling is not swallowed.
    expect(failed).toBe(true)
  })

  it('does not log out or navigate on a 401 from the login endpoint itself', () => {
    configure()
    const auth = TestBed.inject(AuthService)
    auth.token.set('a-jwt-token')
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl')
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    let failed = false
    http
      .post('/api/auth/login', { username: 'florian', password: 'wrong' })
      .subscribe({ error: () => (failed = true) })

    httpMock
      .expectOne('/api/auth/login')
      .flush('Unauthorized', { status: 401, statusText: 'Unauthorized' })

    // LoginPage handles this 401 locally ("Identifiants invalides"); a global
    // logout-and-redirect here would interfere or loop onto /login.
    expect(auth.token()).toBe('a-jwt-token')
    expect(router.navigateByUrl).not.toHaveBeenCalled()
    expect(failed).toBe(true)
  })

  it('leaves non-401 errors alone', () => {
    configure()
    const auth = TestBed.inject(AuthService)
    auth.token.set('a-jwt-token')
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl')
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    http.get('/api/repositories').subscribe({ error: () => undefined })

    httpMock
      .expectOne('/api/repositories')
      .flush('Forbidden', { status: 403, statusText: 'Forbidden' })

    expect(auth.token()).toBe('a-jwt-token')
    expect(router.navigateByUrl).not.toHaveBeenCalled()
  })
})
