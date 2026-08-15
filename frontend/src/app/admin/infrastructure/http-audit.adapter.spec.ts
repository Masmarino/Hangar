import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpAuditAdapter } from './http-audit.adapter'

describe('HttpAuditAdapter', () => {
  it('omits empty filter fields from the request params', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpAuditAdapter],
    })
    const adapter = TestBed.inject(HttpAuditAdapter)
    const httpMock = TestBed.inject(HttpTestingController)

    adapter.query({ aggregate_type: 'Security' }).subscribe()

    const req = httpMock.expectOne((r) => r.url === '/api/audit/events')
    expect(req.request.params.get('aggregate_type')).toBe('Security')
    expect(req.request.params.has('actor_id')).toBe(false)
    req.flush([])
  })
})
