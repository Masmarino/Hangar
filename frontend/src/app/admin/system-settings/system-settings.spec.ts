import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { SystemSettingsAdmin } from './system-settings'
import { adminProviders } from '../infrastructure/admin.providers'

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(SystemSettingsAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock
    .expectOne('/api/admin/settings')
    .flush({ max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true })
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('SystemSettingsAdmin', () => {
  it('loads the current settings into the form', () => {
    const { fixture } = render()

    expect(fixture.componentInstance.maxLoginAttempts()).toBe('10')
    expect(fixture.componentInstance.loginAttemptWindowSeconds()).toBe('300')
    expect(fixture.componentInstance.sessionTtlHours()).toBe('12')
  })

  it('saves valid values', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.setValue('maxLoginAttempts', '5')

    fixture.componentInstance.save()

    const req = httpMock.expectOne('/api/admin/settings')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({
      max_login_attempts: 5,
      login_attempt_window_seconds: 300,
      session_ttl_hours: 12,
      registration_enabled: true,
    })
    req.flush(null)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Paramètres enregistrés.')
  })

  it('saves the registration toggle when turned off', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.registrationEnabled.set(false)

    fixture.componentInstance.save()

    const req = httpMock.expectOne('/api/admin/settings')
    expect(req.request.body).toEqual({
      max_login_attempts: 10,
      login_attempt_window_seconds: 300,
      session_ttl_hours: 12,
      registration_enabled: false,
    })
    req.flush(null)
  })

  it('rejects an out-of-range value without sending a request', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.setValue('maxLoginAttempts', '0')
    fixture.detectChanges()

    fixture.componentInstance.save()

    httpMock.expectNone('/api/admin/settings')
    expect(fixture.componentInstance.hasErrors()).toBe(true)
  })

  it('hides a field error until a save is attempted, then reveals it', () => {
    const { fixture } = render()
    fixture.componentInstance.setValue('maxLoginAttempts', '0')
    const field = fixture.componentInstance.fields.find((f) => f.key === 'maxLoginAttempts')!

    expect(fixture.componentInstance.fieldError(field)).toBeNull()
    expect(fixture.componentInstance.hasErrors()).toBe(false)

    fixture.componentInstance.save()

    expect(fixture.componentInstance.fieldError(field)).toContain('entre')
    expect(fixture.componentInstance.hasErrors()).toBe(true)
  })

  it('rejects a non-integer value', () => {
    const { fixture } = render()
    fixture.componentInstance.setValue('sessionTtlHours', 'abc')
    // Errors stay hidden until a save is attempted.
    fixture.componentInstance.save()

    const field = fixture.componentInstance.fields.find((f) => f.key === 'sessionTtlHours')!
    expect(fixture.componentInstance.fieldError(field)).toContain('entier')
  })

  it('shows a generic error message when the save request fails', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.save()

    httpMock
      .expectOne('/api/admin/settings')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Échec de la mise à jour des paramètres.')
  })
})
