import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { PasskeySettings } from './passkey-settings'
import { mfaProviders } from '../infrastructure/mfa.providers'
import { ToastService } from '../../shared/toast.service'

function stubCredentialsSupported(supported: boolean): void {
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: supported
      ? { create: () => Promise.resolve(null), get: () => Promise.resolve(null) }
      : undefined,
  })
}

function render(passkeys: { id: string; name: string; created_at: string }[] = []) {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...mfaProviders],
  })
  const fixture = TestBed.createComponent(PasskeySettings)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock.expectOne('/api/me/mfa/passkey').flush(passkeys)
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('PasskeySettings', () => {
  afterEach(() => {
    TestBed.inject(HttpTestingController).verify()
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('shows an unsupported message when the browser has no WebAuthn support', () => {
    stubCredentialsSupported(false)
    const { fixture } = render([])

    expect(fixture.componentInstance.supported).toBe(false)
    expect(fixture.nativeElement.textContent).toContain('ne prend pas en charge')
  })

  it('lists registered passkeys', () => {
    stubCredentialsSupported(true)
    const { fixture } = render([{ id: 'p1', name: 'MacBook', created_at: '2026-01-01T00:00:00Z' }])

    expect(fixture.componentInstance.passkeys().length).toBe(1)
    expect(fixture.nativeElement.textContent).toContain('MacBook')
  })

  it('registers a new passkey end to end', async () => {
    stubCredentialsSupported(true)
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        create: () =>
          Promise.resolve({
            id: 'cred-1',
            type: 'public-key',
            rawId: new Uint8Array([1, 2, 3]).buffer,
            response: {
              attestationObject: new Uint8Array([4, 5, 6]).buffer,
              clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
            },
          }),
      },
    })
    const { fixture, httpMock } = render([])

    fixture.componentInstance.startAdding()
    fixture.componentInstance.newPasskeyName.set('YubiKey')
    const registerPromise = fixture.componentInstance.register()

    const startReq = httpMock.expectOne('/api/me/mfa/passkey/register/start')
    expect(startReq.request.method).toBe('POST')
    startReq.flush({
      challenge_id: 'challenge-1',
      public_key: {
        challenge: 'AQID',
        rp: { id: 'x', name: 'Hangar' },
        user: { id: 'AQID', name: 'florian', displayName: 'florian' },
        pubKeyCredParams: [],
      },
    })
    // Let pending microtasks settle before the next HTTP call shows up.
    await new Promise((resolve) => setTimeout(resolve, 0))

    const finishReq = httpMock.expectOne('/api/me/mfa/passkey/register/finish')
    expect(finishReq.request.method).toBe('POST')
    expect(finishReq.request.body.challenge_id).toBe('challenge-1')
    expect(finishReq.request.body.name).toBe('YubiKey')
    finishReq.flush(null)
    // firstValueFrom resolves a microtask later, so reload()'s GET isn't synchronous.
    await new Promise((resolve) => setTimeout(resolve, 0))

    httpMock
      .expectOne('/api/me/mfa/passkey')
      .flush([{ id: 'cred-1', name: 'YubiKey', created_at: '2026-01-01T00:00:00Z' }])
    await registerPromise
    fixture.detectChanges()

    expect(fixture.componentInstance.addingName()).toBe(false)
    expect(fixture.componentInstance.passkeys().length).toBe(1)
  })

  it('deleting a passkey requires a non-empty password field', () => {
    stubCredentialsSupported(true)
    const { fixture, httpMock } = render([
      { id: 'p1', name: 'MacBook', created_at: '2026-01-01T00:00:00Z' },
    ])

    fixture.componentInstance.delete('p1')
    httpMock.expectNone('/api/me/mfa/passkey/p1')

    fixture.componentInstance.setPasswordFor('p1', 's3cret!')
    fixture.componentInstance.delete('p1')
    const req = httpMock.expectOne('/api/me/mfa/passkey/p1')
    expect(req.request.method).toBe('DELETE')
    expect(req.request.body).toEqual({ current_password: 's3cret!' })
    req.flush(null)
    httpMock.expectOne('/api/me/mfa/passkey').flush([])
  })

  it('shows an error when deletion fails', () => {
    stubCredentialsSupported(true)
    const { fixture, httpMock } = render([
      { id: 'p1', name: 'MacBook', created_at: '2026-01-01T00:00:00Z' },
    ])

    fixture.componentInstance.setPasswordFor('p1', 'wrong')
    fixture.componentInstance.delete('p1')
    httpMock
      .expectOne('/api/me/mfa/passkey/p1')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(TestBed.inject(ToastService).toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: 'Mot de passe incorrect.',
    })
  })

  it('shows an error and stops loading when the initial passkey list fails to load', () => {
    stubCredentialsSupported(true)
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...mfaProviders],
    })
    const fixture = TestBed.createComponent(PasskeySettings)
    const httpMock = TestBed.inject(HttpTestingController)
    fixture.detectChanges()
    httpMock
      .expectOne('/api/me/mfa/passkey')
      .flush(null, { status: 500, statusText: 'Internal Server Error' })
    fixture.detectChanges()

    expect(fixture.componentInstance.loading()).toBe(false)
    expect(fixture.componentInstance.passkeys()).toEqual([])
    expect(fixture.nativeElement.textContent).toContain("Échec du chargement des clés d'accès.")
  })
})
