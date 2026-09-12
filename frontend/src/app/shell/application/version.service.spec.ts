import { TestBed } from '@angular/core/testing'
import { of, throwError } from 'rxjs'
import { VersionService } from './version.service'
import { VERSION_PORT, VersionPort } from './version.port'

describe('VersionService', () => {
  function setup(port: Partial<VersionPort>) {
    TestBed.configureTestingModule({
      providers: [{ provide: VERSION_PORT, useValue: port }],
    })
    return TestBed.inject(VersionService)
  }

  it('populates version from the port', () => {
    const service = setup({ load: () => of({ version: '0.2.3' }) })

    service.load()

    expect(service.version()).toBe('0.2.3')
  })

  it('only calls the port once across repeated load() calls', () => {
    const load = vi.fn().mockReturnValue(of({ version: '0.2.3' }))
    const service = setup({ load })

    service.load()
    service.load()

    expect(load).toHaveBeenCalledTimes(1)
  })

  it('does not permanently give up after a failed request — a later call retries', () => {
    const load = vi
      .fn()
      .mockReturnValueOnce(throwError(() => new Error('network blip')))
      .mockReturnValueOnce(of({ version: '0.2.3' }))
    const service = setup({ load })

    service.load()
    expect(service.version()).toBeNull()

    service.load()

    expect(load).toHaveBeenCalledTimes(2)
    expect(service.version()).toBe('0.2.3')
  })
})
