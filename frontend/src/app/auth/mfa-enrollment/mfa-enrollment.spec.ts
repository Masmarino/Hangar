import { ComponentFixture, TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { of, throwError } from 'rxjs'
import { Tooltip } from '@masmarino/gabarit'
import { MfaEnrollmentPage } from './mfa-enrollment'
import { AuthService } from '../application/auth.service'

describe('MfaEnrollmentPage', () => {
  let fixture: ComponentFixture<MfaEnrollmentPage>
  let component: MfaEnrollmentPage
  let authServiceSpy: {
    startTotpSetup: ReturnType<typeof vi.fn>
    confirmTotpSetup: ReturnType<typeof vi.fn>
    startPasskeySetup: ReturnType<typeof vi.fn>
    finishPasskeySetup: ReturnType<typeof vi.fn>
  }

  beforeEach(() => {
    // No jasmine here (vitest-based runner) — hand-rolled vi.fn() spies stand in.
    authServiceSpy = {
      startTotpSetup: vi.fn(),
      confirmTotpSetup: vi.fn(),
      startPasskeySetup: vi.fn(),
      finishPasskeySetup: vi.fn(),
    }

    TestBed.configureTestingModule({
      imports: [MfaEnrollmentPage],
      providers: [{ provide: AuthService, useValue: authServiceSpy }],
    })
    fixture = TestBed.createComponent(MfaEnrollmentPage)
    component = fixture.componentInstance
    fixture.componentRef.setInput('mfaToken', 'mfa-token-123')
    fixture.detectChanges()
  })

  it('starts in the choice step', () => {
    expect(component.setupStep()).toBe('choice')
  })

  it('explains via a tooltip what the TOTP option requires', () => {
    const tooltip = fixture.debugElement.query(By.directive(Tooltip))

    expect((tooltip.componentInstance as Tooltip).text()).toBe(
      'Nécessite une application comme Google Authenticator, Authy ou 1Password.',
    )
  })

  it('moves to the totp-enroll step and stores the secret on chooseTotpSetup', () => {
    authServiceSpy.startTotpSetup.mockReturnValue(
      of({ secret: 'ABCD1234', otpauth_url: 'otpauth://totp/x' }),
    )

    component.chooseTotpSetup()

    expect(authServiceSpy.startTotpSetup).toHaveBeenCalledWith('mfa-token-123')
    expect(component.setupStep()).toBe('totp-enroll')
    expect(component.totpSecret()).toBe('ABCD1234')
  })

  it('emits completed once backup codes are acknowledged', () => {
    const completedSpy = vi.fn()
    component.completed.subscribe(completedSpy)

    component.finishSetup()

    expect(completedSpy).toHaveBeenCalled()
  })

  it('shows backup codes once TOTP setup is confirmed', () => {
    authServiceSpy.startTotpSetup.mockReturnValue(
      of({
        secret: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/Hangar:florian?secret=JBSWY3DPEHPK3PXP&issuer=Hangar',
      }),
    )
    component.chooseTotpSetup()

    authServiceSpy.confirmTotpSetup.mockReturnValue(
      of({ token: 'a-jwt-token', backup_codes: ['aaaa', 'bbbb'] }),
    )
    component.setupCode.set('123456')
    component.confirmTotpSetup()

    expect(authServiceSpy.confirmTotpSetup).toHaveBeenCalledWith('mfa-token-123', '123456')
    expect(component.setupStep()).toBe('backup-codes')
    expect(component.backupCodes()).toEqual(['aaaa', 'bbbb'])
  })

  // Also ported from the pre-extraction login-page.spec.ts (see note above).
  it('registers a passkey during mandatory setup and emits completed', async () => {
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
    authServiceSpy.startPasskeySetup.mockReturnValue(
      of({
        challenge_id: 'challenge-1',
        public_key: {
          challenge: 'AQID',
          rp: { id: 'x', name: 'Hangar' },
          user: { id: 'AQID', name: 'florian', displayName: 'florian' },
          pubKeyCredParams: [],
        },
      }),
    )
    authServiceSpy.finishPasskeySetup.mockReturnValue(of(undefined))
    const completedSpy = vi.fn()
    component.completed.subscribe(completedSpy)

    component.choosePasskeySetup()
    component.passkeyName.set('YubiKey')
    await component.registerSetupPasskey()

    expect(authServiceSpy.startPasskeySetup).toHaveBeenCalledWith('mfa-token-123')
    expect(authServiceSpy.finishPasskeySetup).toHaveBeenCalledWith(
      'mfa-token-123',
      'challenge-1',
      expect.anything(),
      'YubiKey',
    )
    expect(completedSpy).toHaveBeenCalled()

    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('shows an error and stays on the choice step when starting TOTP setup fails', () => {
    authServiceSpy.startTotpSetup.mockReturnValue(throwError(() => new Error('boom')))

    component.chooseTotpSetup()

    expect(component.setupStep()).toBe('choice')
    expect(component.errorMessage()).toBe(
      "Échec de la préparation de l'application d'authentification.",
    )
    expect(component.submitting()).toBe(false)
  })

  it('shows an error and stays on the code-entry step when TOTP confirmation fails', () => {
    authServiceSpy.startTotpSetup.mockReturnValue(
      of({ secret: 'ABCD1234', otpauth_url: 'otpauth://totp/x' }),
    )
    component.chooseTotpSetup()

    authServiceSpy.confirmTotpSetup.mockReturnValue(throwError(() => new Error('invalid code')))
    component.setupCode.set('000000')
    component.confirmTotpSetup()

    expect(authServiceSpy.confirmTotpSetup).toHaveBeenCalledWith('mfa-token-123', '000000')
    expect(component.setupStep()).toBe('totp-enroll')
    expect(component.errorMessage()).toBe('Code invalide.')
    expect(component.submitting()).toBe(false)
  })
})
