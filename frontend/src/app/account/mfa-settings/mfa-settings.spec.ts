import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Tooltip } from '@masmarino/gabarit'
import { MfaSettings } from './mfa-settings'
import { mfaProviders } from '../infrastructure/mfa.providers'
import { ToastService } from '../../shared/toast.service'

function render(status: { totp_enabled: boolean; backup_codes_remaining: number }) {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...mfaProviders],
  })
  const fixture = TestBed.createComponent(MfaSettings)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock.expectOne('/api/me/mfa').flush(status)
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('MfaSettings', () => {
  afterEach(() => {
    TestBed.inject(HttpTestingController).verify()
  })

  it('shows the activation prompt when disabled', () => {
    const { fixture } = render({ totp_enabled: false, backup_codes_remaining: 0 })

    expect(fixture.componentInstance.state()).toBe('disabled')
  })

  it('shows the enabled state with the remaining backup code count', () => {
    const { fixture } = render({ totp_enabled: true, backup_codes_remaining: 7 })

    expect(fixture.componentInstance.state()).toBe('enabled')
    expect(fixture.nativeElement.textContent).toContain('7')
  })

  it('starts enrollment and fetches a secret and otpauth url', () => {
    const { fixture, httpMock } = render({ totp_enabled: false, backup_codes_remaining: 0 })

    fixture.componentInstance.startEnrollment()

    const req = httpMock.expectOne('/api/me/mfa/totp/enroll')
    expect(req.request.method).toBe('POST')
    req.flush({
      secret: 'JBSWY3DPEHPK3PXP',
      otpauth_url: 'otpauth://totp/Hangar:florian?secret=JBSWY3DPEHPK3PXP&issuer=Hangar',
    })
    fixture.detectChanges()

    expect(fixture.componentInstance.state()).toBe('enrolling')
    expect(fixture.componentInstance.enrollmentSecret()).toBe('JBSWY3DPEHPK3PXP')
  })

  it('confirming with a valid code shows the backup codes once', () => {
    const { fixture, httpMock } = render({ totp_enabled: false, backup_codes_remaining: 0 })
    fixture.componentInstance.startEnrollment()
    httpMock
      .expectOne('/api/me/mfa/totp/enroll')
      .flush({ secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/x' })
    fixture.componentInstance.confirmCode.set('123456')

    fixture.componentInstance.confirmEnrollment()

    const req = httpMock.expectOne('/api/me/mfa/totp/confirm')
    expect(req.request.body).toEqual({ code: '123456' })
    req.flush({ backup_codes: ['aaaa', 'bbbb'] })
    fixture.detectChanges()

    expect(fixture.componentInstance.state()).toBe('backup-codes')
    expect(fixture.componentInstance.backupCodes()).toEqual(['aaaa', 'bbbb'])
  })

  it('shows an error when confirmation fails', () => {
    const { fixture, httpMock } = render({ totp_enabled: false, backup_codes_remaining: 0 })
    fixture.componentInstance.startEnrollment()
    httpMock
      .expectOne('/api/me/mfa/totp/enroll')
      .flush({ secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/x' })
    fixture.componentInstance.confirmCode.set('000000')

    fixture.componentInstance.confirmEnrollment()
    httpMock
      .expectOne('/api/me/mfa/totp/confirm')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Code invalide.')
  })

  it('disabling with the wrong password shows an error and reloads status afterwards on success', () => {
    const { fixture, httpMock } = render({ totp_enabled: true, backup_codes_remaining: 5 })
    fixture.componentInstance.disablePassword.set('wrong')

    fixture.componentInstance.disable()
    httpMock.expectOne('/api/me/mfa/totp').flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()
    expect(TestBed.inject(ToastService).toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: 'Mot de passe incorrect.',
    })

    fixture.componentInstance.disablePassword.set('correct')
    fixture.componentInstance.disable()
    const req = httpMock.expectOne('/api/me/mfa/totp')
    expect(req.request.method).toBe('DELETE')
    expect(req.request.body).toEqual({ current_password: 'correct' })
    req.flush(null)
    httpMock.expectOne('/api/me/mfa').flush({ totp_enabled: false, backup_codes_remaining: 0 })
    fixture.detectChanges()

    expect(fixture.componentInstance.state()).toBe('disabled')
  })

  it('regenerating backup codes shows the new set once', () => {
    const { fixture, httpMock } = render({ totp_enabled: true, backup_codes_remaining: 3 })
    fixture.componentInstance.regeneratePassword.set('correct')

    fixture.componentInstance.regenerateBackupCodes()
    const req = httpMock.expectOne('/api/me/mfa/backup-codes/regenerate')
    expect(req.request.body).toEqual({ current_password: 'correct' })
    req.flush({ backup_codes: ['cccc', 'dddd'] })
    fixture.detectChanges()

    expect(fixture.componentInstance.regeneratedCodes()).toEqual(['cccc', 'dddd'])
  })

  it('explains via tooltips what regenerating codes and disabling TOTP do', () => {
    const { fixture } = render({ totp_enabled: true, backup_codes_remaining: 5 })

    const tooltips = fixture.debugElement.queryAll(By.directive(Tooltip))
    const texts = tooltips.map((t) => (t.componentInstance as Tooltip).text())

    expect(texts).toContain('Les anciens codes de secours cesseront de fonctionner immédiatement.')
    expect(texts).toContain('Le compte ne demandera plus de code à la connexion.')
  })
})
