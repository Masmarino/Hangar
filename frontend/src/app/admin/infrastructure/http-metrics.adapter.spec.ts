import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpMetricsAdapter } from './http-metrics.adapter'

describe('HttpMetricsAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpMetricsAdapter],
    })
    return {
      adapter: TestBed.inject(HttpMetricsAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('fetches per-repository usage', () => {
    const { adapter, httpMock } = setup()

    adapter.usage().subscribe((usages) => expect(usages[0].used_bytes).toBe(1024))
    httpMock
      .expectOne('/api/admin/metrics')
      .flush([{ repository_id: 'r1', name: 'my-repo', used_bytes: 1024 }])
  })

  it('fetches health status', () => {
    const { adapter, httpMock } = setup()

    adapter.health().subscribe((status) => {
      expect(status.database.status).toBe('up')
      expect(status.database.active_connections).toBe(2)
      expect(status.storage.free_bytes).toBe(500)
      expect(status.uptime_seconds).toBe(120)
    })
    httpMock.expectOne('/api/admin/health').flush({
      database: {
        status: 'up',
        detail: null,
        response_time_ms: 3,
        active_connections: 2,
        max_connections: 10,
        server_version: '18.0',
      },
      storage: { status: 'up', detail: null, used_bytes: 500, free_bytes: 500, total_bytes: 1000 },
      uptime_seconds: 120,
    })
  })

  it('fetches admin stats', () => {
    const { adapter, httpMock } = setup()

    adapter.stats().subscribe()
    const req = httpMock.expectOne('/api/admin/stats')
    req.flush({ total_users: 3, total_repositories: 2, total_active_permissions: 4 })

    expect(req.request.method).toBe('GET')
  })

  it('fetches metrics history without a days param by default', () => {
    const { adapter, httpMock } = setup()

    adapter.history().subscribe()
    const req = httpMock.expectOne('/api/admin/metrics/history')
    req.flush([
      {
        recorded_at: '2026-01-01T00:00:00Z',
        total_users: 1,
        total_repositories: 1,
        total_storage_bytes: 100,
      },
    ])

    expect(req.request.method).toBe('GET')
    expect(req.request.params.has('days')).toBe(false)
  })

  it('passes the days param when given', () => {
    const { adapter, httpMock } = setup()

    adapter.history(7).subscribe()
    const req = httpMock.expectOne((r) => r.url === '/api/admin/metrics/history')
    req.flush([])

    expect(req.request.params.get('days')).toBe('7')
  })
})
