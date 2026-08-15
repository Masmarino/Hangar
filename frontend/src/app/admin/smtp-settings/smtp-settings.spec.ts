import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { SmtpSettingsAdmin } from './smtp-settings'
import { adminProviders } from '../infrastructure/admin.providers'

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
    req.flush(null)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Paramètres enregistrés.')
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

  it('shows a generic error message when the save request fails', () => {
    const { fixture, httpMock } = render(null)
    fixture.componentInstance.host.set('smtp.example.com')
    fixture.componentInstance.username.set('hangar@example.com')
    fixture.componentInstance.password.set('s3cret')
    fixture.componentInstance.fromAddress.set('hangar@example.com')

    fixture.componentInstance.save()

    httpMock
      .expectOne('/api/admin/settings/smtp')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain(
      'Échec de la mise à jour des paramètres SMTP.',
    )
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
    req.flush(null)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('E-mail de test envoyé.')
  })

  it('shows an error message when the test email fails to send', () => {
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

    httpMock
      .expectOne('/api/admin/settings/smtp/test')
      .flush(null, { status: 500, statusText: 'Internal Server Error' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain("Échec de l'envoi de l'e-mail de test.")
  })
})
