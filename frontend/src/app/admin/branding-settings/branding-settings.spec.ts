import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Tooltip } from '@masmarino/gabarit'
import { BrandingSettingsAdmin } from './branding-settings'
import { adminProviders } from '../infrastructure/admin.providers'
import { ToastService } from '../../shared/toast.service'

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(BrandingSettingsAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock
    .expectOne((r) => r.url === '/api/admin/branding/logo' && r.method === 'GET')
    .flush(new Blob(['logo-bytes'], { type: 'image/png' }))
  httpMock
    .expectOne((r) => r.url === '/api/admin/branding/favicon' && r.method === 'GET')
    .flush(new Blob(['favicon-bytes'], { type: 'image/png' }))
  fixture.detectChanges()
  return { fixture, httpMock }
}

function selectFile(fixture: ReturnType<typeof render>['fixture'], which: 'logo' | 'favicon') {
  const file = new File(['fake-image-bytes'], which === 'logo' ? 'logo.png' : 'favicon.ico', {
    type: 'image/png',
  })
  const handler = which === 'logo' ? 'onLogoFileSelected' : 'onFaviconFileSelected'
  fixture.componentInstance[handler]({ target: { files: [file] } } as unknown as Event)
  return file
}

function selectOversizedFile(
  fixture: ReturnType<typeof render>['fixture'],
  which: 'logo' | 'favicon',
) {
  const file = new File(['x'], which === 'logo' ? 'logo.png' : 'favicon.ico', {
    type: 'image/png',
  })
  // File.size is read-only and too small for the tiny string above, so override it directly.
  Object.defineProperty(file, 'size', { value: 2 * 1024 * 1024 + 1 })
  const handler = which === 'logo' ? 'onLogoFileSelected' : 'onFaviconFileSelected'
  const input = { files: [file], value: 'logo.png' }
  fixture.componentInstance[handler]({ target: input } as unknown as Event)
  return input
}

describe('BrandingSettingsAdmin', () => {
  beforeEach(() => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('fetches the logo and favicon from the authenticated, organization-scoped endpoint and renders them', () => {
    const { fixture } = render()

    expect(fixture.componentInstance.logoPreviewUrl()).toBe('blob:mock')
    expect(fixture.componentInstance.faviconPreviewUrl()).toBe('blob:mock')
    expect(fixture.nativeElement.querySelector('.branding-settings__logo-preview')).toBeTruthy()
    expect(fixture.nativeElement.querySelector('.branding-settings__favicon-preview')).toBeTruthy()
  })

  it('disables the logo import button until a file is selected', () => {
    const { fixture } = render()
    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()

    selectFile(fixture, 'logo')

    expect(fixture.componentInstance.selectedLogoFile()).not.toBeNull()
  })

  it('uploads the selected logo and refetches the preview on success', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'logo')

    fixture.componentInstance.uploadLogo()

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/logo' && r.method === 'PUT')
      .flush(null)
    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/logo' && r.method === 'GET')
      .flush(new Blob(['new-logo-bytes'], { type: 'image/png' }))
  })

  it('shows the server error message in a toast when a logo upload is rejected', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'logo')

    fixture.componentInstance.uploadLogo()

    const toastService = TestBed.inject(ToastService)
    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/logo' && r.method === 'PUT')
      .flush({ error: 'format non supporté' }, { status: 400, statusText: 'Bad Request' })

    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: 'format non supporté',
    })
  })

  it('resets the logo and refetches the preview', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.resetLogo()

    const req = httpMock.expectOne(
      (r) => r.url === '/api/admin/branding/logo' && r.method === 'DELETE',
    )
    req.flush(null)

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/logo' && r.method === 'GET')
      .flush(new Blob(['default-logo-bytes'], { type: 'image/png' }))
  })

  it('uploads the selected favicon and refetches the preview on success', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'favicon')

    fixture.componentInstance.uploadFavicon()

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/favicon' && r.method === 'PUT')
      .flush(null)

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/favicon' && r.method === 'GET')
      .flush(new Blob(['new-favicon-bytes'], { type: 'image/png' }))
  })

  it('resets the favicon and refetches the preview', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.resetFavicon()

    const req = httpMock.expectOne(
      (r) => r.url === '/api/admin/branding/favicon' && r.method === 'DELETE',
    )
    req.flush(null)

    httpMock
      .expectOne((r) => r.url === '/api/admin/branding/favicon' && r.method === 'GET')
      .flush(new Blob(['default-favicon-bytes'], { type: 'image/png' }))
  })

  it('rejects an oversized logo file before any upload, clearing the input', () => {
    const { fixture, httpMock } = render()

    const input = selectOversizedFile(fixture, 'logo')

    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()
    expect(fixture.componentInstance.logoError()).toContain('2 Mo')
    expect(input.value).toBe('')
    httpMock.expectNone((r) => r.url === '/api/admin/branding/logo' && r.method === 'PUT')
  })

  it('rejects an oversized favicon file before any upload, clearing the input', () => {
    const { fixture, httpMock } = render()

    const input = selectOversizedFile(fixture, 'favicon')

    expect(fixture.componentInstance.selectedFaviconFile()).toBeNull()
    expect(fixture.componentInstance.faviconError()).toContain('2 Mo')
    expect(input.value).toBe('')
    httpMock.expectNone((r) => r.url === '/api/admin/branding/favicon' && r.method === 'PUT')
  })

  it('re-fetches the logo and favicon when organizationId changes to a different organization — the component is reused, not recreated, across a super-admin switching organizations', () => {
    const { fixture, httpMock } = render()

    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
    httpMock
      .expectOne(
        (r) => r.url === '/api/admin/branding/logo' && r.params.get('organization_id') === 'org-1',
      )
      .flush(new Blob(['org1-logo'], { type: 'image/png' }))
    httpMock
      .expectOne(
        (r) =>
          r.url === '/api/admin/branding/favicon' && r.params.get('organization_id') === 'org-1',
      )
      .flush(new Blob(['org1-favicon'], { type: 'image/png' }))
    fixture.detectChanges()

    fixture.componentRef.setInput('organizationId', 'org-2')
    fixture.detectChanges()
    httpMock
      .expectOne(
        (r) => r.url === '/api/admin/branding/logo' && r.params.get('organization_id') === 'org-2',
      )
      .flush(new Blob(['org2-logo'], { type: 'image/png' }))
    httpMock
      .expectOne(
        (r) =>
          r.url === '/api/admin/branding/favicon' && r.params.get('organization_id') === 'org-2',
      )
      .flush(new Blob(['org2-favicon'], { type: 'image/png' }))
    fixture.detectChanges()
  })

  it('explains what each reset button does via a tooltip', () => {
    const { fixture } = render()

    const tooltips = fixture.debugElement.queryAll(By.directive(Tooltip))
    const texts = tooltips.map((t) => (t.componentInstance as Tooltip).text())

    expect(texts).toContain('Revient au logo par défaut de Hangar.')
    expect(texts).toContain('Revient au favicon par défaut de Hangar.')
  })
})
