import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpApiTokenAdapter } from './http-api-token.adapter'

describe('HttpApiTokenAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpApiTokenAdapter],
    })
    return {
      adapter: TestBed.inject(HttpApiTokenAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('lists tokens', () => {
    const { adapter, httpMock } = setup()

    adapter.list().subscribe((tokens) => {
      expect(tokens.length).toBe(1)
      expect(tokens[0].label).toBe('laptop')
    })

    const req = httpMock.expectOne('/api/tokens')
    expect(req.request.method).toBe('GET')
    req.flush([
      { id: '1', label: 'laptop', created_at: '2026-01-01T00:00:00Z', last_used_at: null },
    ])
    httpMock.verify()
  })

  it('creates a token and surfaces the one-time plaintext value', () => {
    const { adapter, httpMock } = setup()

    adapter.create('laptop').subscribe((result) => {
      expect(result.token).toBe('hgr_secret')
    })

    const req = httpMock.expectOne('/api/tokens')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ label: 'laptop' })
    req.flush({ id: '1', token: 'hgr_secret' })
    httpMock.verify()
  })

  it('revokes a token', () => {
    const { adapter, httpMock } = setup()

    adapter.revoke('1').subscribe()

    const req = httpMock.expectOne('/api/tokens/1')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)
    httpMock.verify()
  })
})
