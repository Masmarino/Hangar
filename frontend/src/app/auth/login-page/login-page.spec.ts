import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Router, provideRouter } from '@angular/router'
import { LoginPage } from './login-page'
import { MfaEnrollmentPage } from '../mfa-enrollment/mfa-enrollment'
import { authProviders } from '../infrastructure/auth.providers'

describe('LoginPage', () => {
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...authProviders,
      ],
    })
    httpMock = TestBed.inject(HttpTestingController)
  })

  // ngOnInit fires GET /api/auth/sso/config on every component creation — flush it with
  // `{ type: null }` (local login) unless a test wants to exercise the LDAP or OIDC path.
  function flushSsoConfig(type: 'ldap' | 'oidc' | null = null, registrationEnabled = true): void {
    httpMock
      .expectOne('/api/auth/sso/config')
      .flush({ type, registration_enabled: registrationEnabled })
  }

  afterEach(() => {
    sessionStorage.clear()
    httpMock.verify()
    vi.restoreAllMocks()
  })

  it('creates the component', () => {
    const fixture = TestBed.createComponent(LoginPage)
    expect(fixture.componentInstance).toBeTruthy()
  })

  it('shows the "Créer un compte" link when registration is enabled', () => {
    const fixture = TestBed.createComponent(LoginPage)
    fixture.detectChanges()
    flushSsoConfig(null, true)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Créer un compte')
  })

  it('hides the "Créer un compte" link when the admin has disabled registration', () => {
    const fixture = TestBed.createComponent(LoginPage)
    fixture.detectChanges()
    flushSsoConfig(null, false)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Créer un compte')
  })

  it('does not send a second login request when submit is called again while one is in flight', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })

    component.submit()
    expect(component.submitting()).toBe(true)

    // A second submit attempt while the first request is still pending must be a no-op.
    component.submit()

    // If the guard didn't work, a second matching request would exist here and
    // httpMock.expectOne would throw "matches multiple requests".
    const req = httpMock.expectOne('/api/auth/login')
    expect(req.request.method).toBe('POST')
  })

  it('posts to the LDAP endpoint when the organization uses LDAP', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig('ldap')
    component.form.setValue({ username: 'florian', password: 's3cret!' })

    component.submit()

    const req = httpMock.expectOne('/api/auth/sso/ldap')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ username: 'florian', password: 's3cret!' })
    req.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
  })

  it('shows the OIDC redirect link when the organization uses OIDC', () => {
    const fixture = TestBed.createComponent(LoginPage)
    fixture.detectChanges()
    flushSsoConfig('oidc')
    fixture.detectChanges()

    const link: HTMLAnchorElement = fixture.nativeElement.querySelector(
      'a[href="/api/auth/sso/oidc/login"]',
    )
    expect(link).toBeTruthy()
    expect(fixture.nativeElement.querySelector('form')).toBeNull()
  })

  it('switches to the MFA code form when the login response requires a second factor', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })

    component.submit()

    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: true,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    expect(component.mfaToken()).toBe('pending-token')
  })

  // Regression test: an account with only a passkey (no TOTP ever confirmed) used to still
  // see a "enter your code" field on this screen — meaningless and confusing, since no such
  // code exists. The verify step must show only the factor(s) the account actually has.
  it('shows only the passkey button, not the code form, when the account has no TOTP', () => {
    // passkeysSupported() is read once at construction — jsdom has no WebAuthn API by
    // default, so this must be in place before the component is created.
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { create: () => Promise.resolve() },
    })
    const fixture = TestBed.createComponent(LoginPage)
    fixture.detectChanges()
    flushSsoConfig()
    fixture.componentInstance.form.setValue({ username: 'florian', password: 's3cret!' })
    fixture.componentInstance.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: true,
    })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Code de vérification')
    expect(fixture.nativeElement.textContent).toContain("Utiliser une clé d'accès")
  })

  it('shows only the code form, not the passkey button, when the account has no passkey', () => {
    const fixture = TestBed.createComponent(LoginPage)
    fixture.detectChanges()
    flushSsoConfig()
    fixture.componentInstance.form.setValue({ username: 'florian', password: 's3cret!' })
    fixture.componentInstance.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: true,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Code de vérification')
    expect(fixture.nativeElement.textContent).not.toContain("Utiliser une clé d'accès")
  })

  it('submits the TOTP code and redirects on success', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })
    component.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: true,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    component.mfaForm.setValue({ code: '123456' })
    component.submitMfa()

    const req = httpMock.expectOne('/api/auth/mfa/verify')
    expect(req.request.body).toEqual({
      mfa_token: 'pending-token',
      code: '123456',
      backup_code: undefined,
    })
    req.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })

    expect(router.navigateByUrl).toHaveBeenCalledWith('/')
  })

  it('submits a backup code instead of a TOTP code once toggled', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })
    component.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: true,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    component.toggleBackupCode()
    component.mfaForm.setValue({ code: 'abc123' })
    component.submitMfa()

    const req = httpMock.expectOne('/api/auth/mfa/verify')
    expect(req.request.body).toEqual({
      mfa_token: 'pending-token',
      code: undefined,
      backup_code: 'abc123',
    })
    req.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
  })

  it('shows an error message when the mfa code is rejected', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })
    component.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: true,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    component.mfaForm.setValue({ code: '000000' })
    component.submitMfa()
    httpMock
      .expectOne('/api/auth/mfa/verify')
      .flush(null, { status: 401, statusText: 'Unauthorized' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Code invalide.')
  })

  it('logs in with a passkey when the second factor is a passkey', async () => {
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        get: () =>
          Promise.resolve({
            id: 'cred-1',
            type: 'public-key',
            rawId: new Uint8Array([1, 2, 3]).buffer,
            response: {
              authenticatorData: new Uint8Array([4, 5, 6]).buffer,
              clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
              signature: new Uint8Array([10, 11, 12]).buffer,
              userHandle: null,
            },
          }),
      },
    })
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })
    component.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: true,
    })
    fixture.detectChanges()

    const loginPromise = component.submitPasskey()

    const startReq = httpMock.expectOne('/api/auth/mfa/passkey/start')
    expect(startReq.request.body).toEqual({ mfa_token: 'pending-token' })
    startReq.flush({
      challenge_id: 'challenge-1',
      public_key: {
        challenge: 'AQID',
        rpId: 'x',
        allowCredentials: [],
        userVerification: 'required',
      },
    })
    await new Promise((resolve) => setTimeout(resolve, 0))

    const finishReq = httpMock.expectOne('/api/auth/mfa/passkey/finish')
    expect(finishReq.request.body.mfa_token).toBe('pending-token')
    expect(finishReq.request.body.challenge_id).toBe('challenge-1')
    finishReq.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
    await loginPromise

    expect(router.navigateByUrl).toHaveBeenCalledWith('/')

    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('renders app-mfa-enrollment with the pending mfa token when the account has no second factor enrolled yet', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    fixture.detectChanges()
    flushSsoConfig()
    component.form.setValue({ username: 'florian', password: 's3cret!' })

    component.submit()
    httpMock.expectOne('/api/auth/login').flush({
      token: null,
      mfa_token: 'pending-token',
      mfa_setup_required: true,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
    fixture.detectChanges()

    expect(component.mfaSetupRequired()).toBe(true)
    const enrollment = fixture.debugElement.query(By.directive(MfaEnrollmentPage))
    expect(enrollment).toBeTruthy()
    expect((enrollment.componentInstance as MfaEnrollmentPage).mfaToken()).toBe('pending-token')
  })

  it('redirects home when the extracted enrollment component reports completion', () => {
    const fixture = TestBed.createComponent(LoginPage)
    const component = fixture.componentInstance
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
    fixture.detectChanges()
    flushSsoConfig()

    component.onEnrollmentCompleted()

    expect(router.navigateByUrl).toHaveBeenCalledWith('/')
  })
})
