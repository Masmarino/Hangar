import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpVersionAdapter } from './http-version.adapter'

describe('HttpVersionAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpVersionAdapter],
    })
    return {
      adapter: TestBed.inject(HttpVersionAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('fetches the running version from /api/version', () => {
    const { adapter, httpMock } = setup()

    adapter.load().subscribe((response) => expect(response.version).toBe('0.2.3'))
    httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
  })
})
