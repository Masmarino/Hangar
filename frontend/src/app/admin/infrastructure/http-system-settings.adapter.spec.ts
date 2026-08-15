import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpSystemSettingsAdapter } from './http-system-settings.adapter'

describe('HttpSystemSettingsAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpSystemSettingsAdapter],
    })
    return {
      adapter: TestBed.inject(HttpSystemSettingsAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('fetches the current settings', () => {
    const { adapter, httpMock } = setup()

    adapter.get().subscribe((settings) => expect(settings.max_login_attempts).toBe(10))
    httpMock
      .expectOne('/api/admin/settings')
      .flush({ max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true })
  })

  it('sends an update as a PUT request', () => {
    const { adapter, httpMock } = setup()

    adapter
      .update({ max_login_attempts: 5, login_attempt_window_seconds: 60, session_ttl_hours: 1, registration_enabled: false })
      .subscribe()
    const req = httpMock.expectOne('/api/admin/settings')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({
      max_login_attempts: 5,
      login_attempt_window_seconds: 60,
      session_ttl_hours: 1,
      registration_enabled: false,
    })
    req.flush(null)
  })
})
