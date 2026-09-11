import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { SystemSettingsService } from './system-settings.service'
import { SYSTEM_SETTINGS_PORT, SystemSettingsPort } from './system-settings.port'

describe('SystemSettingsService', () => {
  function setup(port: Partial<SystemSettingsPort>) {
    TestBed.configureTestingModule({
      providers: [{ provide: SYSTEM_SETTINGS_PORT, useValue: port }],
    })
    return TestBed.inject(SystemSettingsService)
  }

  it('delegates get() to the port', () => {
    const get = vi.fn().mockReturnValue(of({}))
    setup({ get }).get()

    expect(get).toHaveBeenCalled()
  })

  it('delegates update() to the port', () => {
    const settings = {
      max_login_attempts: 5,
      login_attempt_window_seconds: 60,
      session_ttl_hours: 1,
      registration_enabled: true,
    }
    const update = vi.fn().mockReturnValue(of(undefined))
    setup({ update }).update(settings)

    expect(update).toHaveBeenCalledWith(settings, undefined)
  })
})
