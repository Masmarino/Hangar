import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Tooltip } from '@masmarino/gabarit'
import { SmtpSettingsAdmin } from './smtp-settings'
import { adminProviders } from '../infrastructure/admin.providers'
import { ToastService } from '../../shared/toast.service'

function render(existing: object | null = null) {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(SmtpSettingsAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock.expectOne('/api/admin/settings/smtp').flush(existing)
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('SmtpSettingsAdmin', () => {
  it('starts with an empty form when SMTP has never been configured', () => {
    const { fixture } = render(null)

    expect(fixture.componentInstance.host()).toBe('')
    expect(fixture.componentInstance.passwordSet()).toBe(false)
  })

  it('shows no field errors and does not disable Enregistrer before any save attempt, even though every required field starts empty', () => {
    const { fixture } = render(null)

    expect(fixture.componentInstance.hostError()).toBeNull()
    expect(fixture.componentInstance.usernameError()).toBeNull()
    expect(fixture.componentInstance.passwordError()).toBeNull()
    expect(fixture.componentInstance.fromAddressError()).toBeNull()
    expect(fixture.componentInstance.hasErrors()).toBe(false)
  })

  it('reveals the field errors once a save is attempted on an invalid form', () => {
    const { fixture, httpMock } = render(null)

    fixture.componentInstance.save()

    httpMock.expectNone('/api/admin/settings/smtp')
    expect(fixture.componentInstance.hostError()).toBe("L'hôte est requis.")
    expect(fixture.componentInstance.usernameError()).toBe("L'identifiant est requis.")
  })

  it('loads existing settings into the form without ever receiving the password', () => {
    const { fixture } = render({
      host: 'smtp.example.com',
      port: 587,
      username: 'hangar@example.com',
      from_name: 'Acme Corp',
      from_address: 'hangar@example.com',
      security: 'start_tls',
      password_set: true,
    })

    expect(fixture.componentInstance.host()).toBe('smtp.example.com')
    expect(fixture.componentInstance.port()).toBe('587')
    expect(fixture.componentInstance.fromName()).toBe('Acme Corp')
    expect(fixture.componentInstance.passwordSet()).toBe(true)
    expect(fixture.componentInstance.password()).toBe('')
  })

  it('requires a password on first-time configuration', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.fromAddress.set('hangar@example.com')

    fixture.componentInstance.save()

    httpMock.expectNone('/api/admin/settings/smtp')
    expect(fixture.componentInstance.hasErrors()).toBe(true)
  })

  it('saves valid settings and leaves the password blank afterwards', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.password.set('s3cret')
    fixture.componentInstance.fromAddress.set('hangar@example.com')

    fixture.componentInstance.save()

    const req = httpMock.expectOne('/api/admin/settings/smtp')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({
      host: 'smtp.example.com',
      port: 587,
      username: 'hangar@example.com',
      password: 's3cret',
      from_name: 'Hangar',
      from_address: 'hangar@example.com',
      security: 'start_tls',
    })
    const toastService = TestBed.inject(ToastService)
    req.flush(null)
    fixture.detectChanges()

    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'success',
      message: 'Paramètres SMTP enregistrés.',
    })
    expect(fixture.componentInstance.password()).toBe('')
    expect(fixture.componentInstance.passwordSet()).toBe(true)
  })

  it('omits the password from the update request when left blank on an already-configured instance', () => {
    const { fixture, httpMock } = render({
      host: 'smtp.example.com',
      port: 587,
      username: 'hangar@example.com',
      from_name: 'Hangar',
      from_address: 'hangar@example.com',
      security: 'start_tls',
      password_set: true,
    })

    fixture.componentInstance.save()

    const req = httpMock.expectOne('/api/admin/settings/smtp')
    expect(req.request.body.password).toBeUndefined()
    req.flush(null)
  })

  it('rejects a from_address without an @ sign', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.password.set('s3cret')
    fixture.componentInstance.fromAddress.set('not-an-email')

    fixture.componentInstance.save()

    httpMock.expectNone('/api/admin/settings/smtp')
    expect(fixture.componentInstance.hasErrors()).toBe(true)
  })

  it('rejects an empty from name', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.password.set('s3cret')
    fixture.componentInstance.fromAddress.set('hangar@example.com')
    fixture.componentInstance.fromName.set('  ')

    fixture.componentInstance.save()

    httpMock.expectNone('/api/admin/settings/smtp')
    expect(fixture.componentInstance.hasErrors()).toBe(true)
  })

  it('shows a generic error toast when the save request fails', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.password.set('s3cret')
    fixture.componentInstance.fromAddress.set('hangar@example.com')

    fixture.componentInstance.save()

    const toastService = TestBed.inject(ToastService)
    httpMock
      .expectOne('/api/admin/settings/smtp')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: 'Échec de la mise à jour des paramètres SMTP.',
    })
  })

  it('sends a test email to the given recipient', () => {
    const { fixture, httpMock } = render({
      host: 'smtp.example.com',
      port: 587,
      username: 'hangar@example.com',
      from_name: 'Hangar',
      from_address: 'hangar@example.com',
      security: 'start_tls',
      password_set: true,
    })
    fixture.componentInstance.testRecipient.set('admin@example.com')

    fixture.componentInstance.sendTest()

    const req = httpMock.expectOne('/api/admin/settings/smtp/test')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ to: 'admin@example.com' })
    const toastService = TestBed.inject(ToastService)
    req.flush(null)
    fixture.detectChanges()

    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'success',
      message: 'E-mail de test envoyé.',
    })
  })

  it('shows an error toast when the test email fails to send', () => {
    const { fixture, httpMock } = render({
      host: 'smtp.example.com',
      port: 587,
      username: 'hangar@example.com',
      from_name: 'Hangar',
      from_address: 'hangar@example.com',
      security: 'start_tls',
      password_set: true,
    })
    fixture.componentInstance.testRecipient.set('admin@example.com')

    fixture.componentInstance.sendTest()

    const toastService = TestBed.inject(ToastService)
    httpMock
      .expectOne('/api/admin/settings/smtp/test')
      .flush(null, { status: 500, statusText: 'Internal Server Error' })
    fixture.detectChanges()

    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: "Échec de l'envoi de l'e-mail de test. Vérifiez la configuration.",
    })
  })

  it('re-fetches (and resets stale fields) when organizationId changes to a different organization — the component is reused, not recreated, across a super-admin switching organizations', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
    httpMock.expectOne('/api/admin/settings/smtp?organization_id=org-1').flush({
      host: 'org1.example.com',
      port: 587,
      username: 'org1@example.com',
      from_name: 'Org1',
      from_address: 'org1@example.com',
      security: 'start_tls',
      password_set: true,
    })
    fixture.detectChanges()
    expect(fixture.componentInstance.host()).toBe('org1.example.com')

    fixture.componentRef.setInput('organizationId', 'org-2')
    fixture.detectChanges()
    // org-2 has no SMTP configured — must not still show org-1's settings.
    httpMock.expectOne('/api/admin/settings/smtp?organization_id=org-2').flush(null)
    fixture.detectChanges()

    expect(fixture.componentInstance.host()).toBe('')
    expect(fixture.componentInstance.fromName()).toBe('Hangar')
    expect(fixture.componentInstance.passwordSet()).toBe(false)
  })

  it('explains via a tooltip that the test email uses the saved configuration, not the unsaved form', () => {
    const { fixture } = render(null)

    const tooltip = fixture.debugElement.query(By.directive(Tooltip))

    expect((tooltip.componentInstance as Tooltip).text()).toBe(
      'Utilise la configuration déjà enregistrée, pas les modifications du formulaire ci-dessus.',
    )
  })
})
