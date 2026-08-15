import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { ExportAdmin } from './export'
import { adminProviders } from '../infrastructure/admin.providers'

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(ExportAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('ExportAdmin', () => {
  it('downloads the configuration export when the button is clicked', () => {
    const { fixture, httpMock } = render()
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})

    fixture.componentInstance.downloadConfiguration()

    const req = httpMock.expectOne('/api/admin/export/configuration')
    expect(req.request.responseType).toBe('blob')
    req.flush(new Blob(['{}'], { type: 'application/json' }))

    expect(createObjectURL).toHaveBeenCalled()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock')
    expect(fixture.componentInstance.downloading()).toBe(false)
  })

  it('shows an error message when the export request fails', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.downloadConfiguration()

    httpMock
      .expectOne('/api/admin/export/configuration')
      .flush(null, { status: 500, statusText: 'Internal Server Error' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain("Échec de l'export")
    expect(fixture.componentInstance.downloading()).toBe(false)
  })

  it('imports a configuration file and shows the report', async () => {
    const { fixture, httpMock } = render()
    const file = new File(['{}'], 'config.json', { type: 'application/json' })
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    fixture.componentInstance.onFileSelected({ target: { files: [file] } } as unknown as Event)
    fixture.componentInstance.importConfiguration()

    await Promise.resolve()
    await Promise.resolve()

    const req = httpMock.expectOne('/api/admin/import/configuration')
    req.flush({
      users_created: 2,
      repositories_created: 1,
      permissions_granted: 0,
      invited: ['admin'],
      skipped_no_email: ['member'],
      failed: [],
    })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('2')
    expect(fixture.nativeElement.textContent).toContain('admin')
  })

  it('does not import when the confirmation is declined', () => {
    const { fixture, httpMock } = render()
    const file = new File(['{}'], 'config.json', { type: 'application/json' })
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    fixture.componentInstance.onFileSelected({ target: { files: [file] } } as unknown as Event)
    fixture.componentInstance.importConfiguration()

    httpMock.expectNone('/api/admin/import/configuration')
  })

  it('shows the generic error message when the import request fails with no body', async () => {
    const { fixture, httpMock } = render()
    const file = new File(['{}'], 'config.json', { type: 'application/json' })
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    fixture.componentInstance.onFileSelected({ target: { files: [file] } } as unknown as Event)
    fixture.componentInstance.importConfiguration()

    await Promise.resolve()
    await Promise.resolve()

    httpMock
      .expectOne('/api/admin/import/configuration')
      .flush(null, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain("Échec de l'import de la configuration.")
  })

  it('shows the server-provided error message when the import request fails with a body', async () => {
    const { fixture, httpMock } = render()
    const file = new File(['{}'], 'config.json', { type: 'application/json' })
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    fixture.componentInstance.onFileSelected({ target: { files: [file] } } as unknown as Event)
    fixture.componentInstance.importConfiguration()

    await Promise.resolve()
    await Promise.resolve()

    httpMock
      .expectOne('/api/admin/import/configuration')
      .flush({ error: 'instance non vide' }, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('instance non vide')
    expect(fixture.nativeElement.textContent).not.toContain(
      "Échec de l'import de la configuration.",
    )
  })
})
