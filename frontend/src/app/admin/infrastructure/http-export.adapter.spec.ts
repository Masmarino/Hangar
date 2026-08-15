import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpExportAdapter } from './http-export.adapter'

describe('HttpExportAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpExportAdapter],
    })
    return {
      adapter: TestBed.inject(HttpExportAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('fetches the configuration export as a blob', () => {
    const { adapter, httpMock } = setup()

    adapter.exportConfiguration().subscribe((blob) => expect(blob).toBeInstanceOf(Blob))
    const req = httpMock.expectOne('/api/admin/export/configuration')
    expect(req.request.method).toBe('GET')
    expect(req.request.responseType).toBe('blob')
    req.flush(new Blob(['{}'], { type: 'application/json' }))
  })

  it('posts the parsed file contents and returns the import report', async () => {
    const { adapter, httpMock } = setup()
    const file = new File(
      ['{"users":[],"repositories":[],"permissions":[],"system_settings":{}}'],
      'config.json',
      { type: 'application/json' },
    )
    let result: unknown
    adapter.importConfiguration(file).subscribe((report) => (result = report))

    // file.text() resolves asynchronously before the HTTP request is made.
    await Promise.resolve()
    await Promise.resolve()

    const req = httpMock.expectOne('/api/admin/import/configuration')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({
      users: [],
      repositories: [],
      permissions: [],
      system_settings: {},
    })
    req.flush({
      users_created: 1,
      repositories_created: 0,
      permissions_granted: 0,
      invited: [],
      skipped_no_email: [],
      failed: [],
    })

    expect(result).toEqual({
      users_created: 1,
      repositories_created: 0,
      permissions_granted: 0,
      invited: [],
      skipped_no_email: [],
      failed: [],
    })
  })
})
