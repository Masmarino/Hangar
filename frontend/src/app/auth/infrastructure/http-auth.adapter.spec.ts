import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpAuthAdapter } from './http-auth.adapter'

describe('HttpAuthAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpAuthAdapter],
    })
    return {
      adapter: TestBed.inject(HttpAuthAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('posts username/password to /api/auth/login', () => {
    const { adapter, httpMock } = setup()

    adapter.login('florian', 's3cret!').subscribe()

    const req = httpMock.expectOne('/api/auth/login')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ username: 'florian', password: 's3cret!' })
    req.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
    httpMock.verify()
  })

  it('posts the mfa token, code and backup code to /api/auth/mfa/verify', () => {
    const { adapter, httpMock } = setup()

    adapter.verifyMfa('pending-token', '123456').subscribe()

    const req = httpMock.expectOne('/api/auth/mfa/verify')
    expect(req.request.method).toBe('POST')
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
    httpMock.verify()
  })

  it('posts username/email/password to /api/auth/register', () => {
    const { adapter, httpMock } = setup()

    adapter.register('florian', 'florian@example.com', 's3cret!').subscribe()

    const req = httpMock.expectOne('/api/auth/register')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({
      username: 'florian',
      email: 'florian@example.com',
      password: 's3cret!',
    })
    req.flush({
      token: null,
      mfa_token: 'mfa-token-123',
      mfa_setup_required: true,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
    httpMock.verify()
  })

  it('posts the mfa token to /api/auth/mfa/setup/totp/enroll', () => {
    const { adapter, httpMock } = setup()

    adapter.startTotpSetup('mfa-token-123').subscribe()

    const req = httpMock.expectOne('/api/auth/mfa/setup/totp/enroll')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ mfa_token: 'mfa-token-123' })
    req.flush({ secret: 'ABCDEF', otpauth_url: 'otpauth://totp/hangar?secret=ABCDEF' })
    httpMock.verify()
  })

  it('posts the mfa token and code to /api/auth/mfa/setup/totp/confirm', () => {
    const { adapter, httpMock } = setup()

    adapter.confirmTotpSetup('mfa-token-123', '123456').subscribe()

    const req = httpMock.expectOne('/api/auth/mfa/setup/totp/confirm')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ mfa_token: 'mfa-token-123', code: '123456' })
    req.flush({ token: 'a-jwt-token', backup_codes: ['aaaa-bbbb', 'cccc-dddd'] })
    httpMock.verify()
  })

  it('posts the mfa token to /api/auth/mfa/setup/passkey/start', () => {
    const { adapter, httpMock } = setup()

    adapter.startPasskeySetup('mfa-token-123').subscribe()

    const req = httpMock.expectOne('/api/auth/mfa/setup/passkey/start')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ mfa_token: 'mfa-token-123' })
    req.flush({ challenge_id: 'challenge-123', public_key: { challenge: 'abc' } })
    httpMock.verify()
  })

  it('posts the mfa token, challenge id, credential and name to /api/auth/mfa/setup/passkey/finish', () => {
    const { adapter, httpMock } = setup()

    adapter
      .finishPasskeySetup('mfa-token-123', 'challenge-123', { id: 'cred-1' }, 'My key')
      .subscribe()

    const req = httpMock.expectOne('/api/auth/mfa/setup/passkey/finish')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({
      mfa_token: 'mfa-token-123',
      challenge_id: 'challenge-123',
      credential: { id: 'cred-1' },
      name: 'My key',
    })
    req.flush({
      token: 'a-jwt-token',
      mfa_token: null,
      mfa_setup_required: false,
      mfa_has_totp: false,
      mfa_has_passkey: false,
    })
    httpMock.verify()
  })

  it('gets the sso config from GET /api/auth/sso/config', () => {
    const { adapter, httpMock } = setup()
    adapter.getSsoConfig().subscribe()
    const req = httpMock.expectOne('/api/auth/sso/config')
    expect(req.request.method).toBe('GET')
    req.flush({ type: null, registration_enabled: true })
    httpMock.verify()
  })

  it('posts username/password to /api/auth/sso/ldap', () => {
    const { adapter, httpMock } = setup()
    adapter.loginWithLdap('florian', 's3cret!').subscribe()
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
    httpMock.verify()
  })
})
