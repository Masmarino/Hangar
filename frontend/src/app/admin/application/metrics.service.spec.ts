import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { AdminMetricsService } from './metrics.service'
import { METRICS_PORT, MetricsPort } from './metrics.port'

describe('AdminMetricsService', () => {
  function setup(port: Partial<MetricsPort>) {
    TestBed.configureTestingModule({ providers: [{ provide: METRICS_PORT, useValue: port }] })
    return TestBed.inject(AdminMetricsService)
  }

  it('delegates usage() to the port', () => {
    const usage = vi.fn().mockReturnValue(of([]))
    setup({ usage }).usage()

    expect(usage).toHaveBeenCalled()
  })

  it('delegates health() to the port', () => {
    const health = vi.fn().mockReturnValue(of({}))
    setup({ health }).health()

    expect(health).toHaveBeenCalled()
  })

  it('delegates stats() to the port', () => {
    const stats = vi.fn().mockReturnValue(of({}))
    setup({ stats }).stats()

    expect(stats).toHaveBeenCalled()
  })

  it('delegates history() to the port with the given days', () => {
    const history = vi.fn().mockReturnValue(of([]))
    setup({ history }).history(7)

    expect(history).toHaveBeenCalledWith(7)
  })
})
