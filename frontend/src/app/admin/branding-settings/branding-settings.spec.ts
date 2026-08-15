import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { BrandingSettingsAdmin } from './branding-settings'
import { adminProviders } from '../infrastructure/admin.providers'

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(BrandingSettingsAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
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
  // `File.size` reflects the Blob's real content length, which the tiny string above isn't
  // big enough for — override it directly, same trick browsers themselves can't prevent us from
  // needing here since File.size is normally read-only.
  Object.defineProperty(file, 'size', { value: 2 * 1024 * 1024 + 1 })
  const handler = which === 'logo' ? 'onLogoFileSelected' : 'onFaviconFileSelected'
  const input = { files: [file], value: 'logo.png' }
  fixture.componentInstance[handler]({ target: input } as unknown as Event)
  return input
}

describe('BrandingSettingsAdmin', () => {
  it('renders the logo and favicon previews pointing at the stable branding URLs', () => {
    const { fixture } = render()

    expect(fixture.componentInstance.logoPreviewUrl()).toContain('/api/branding/logo')
    expect(fixture.componentInstance.faviconPreviewUrl()).toContain('/api/branding/favicon')
  })

  it('disables the logo import button until a file is selected', () => {
    const { fixture } = render()
    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()

    selectFile(fixture, 'logo')

    expect(fixture.componentInstance.selectedLogoFile()).not.toBeNull()
  })

  it('uploads the selected logo and bumps the preview version on success', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'logo')
    const versionBefore = fixture.componentInstance.logoVersion()

    fixture.componentInstance.uploadLogo()

    httpMock.expectOne('/api/admin/branding/logo').flush(null)
    expect(fixture.componentInstance.logoVersion()).toBe(versionBefore + 1)
    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()
  })

  it('shows the server error message when a logo upload is rejected', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'logo')

    fixture.componentInstance.uploadLogo()

    httpMock
      .expectOne('/api/admin/branding/logo')
      .flush({ error: 'format non supporté' }, { status: 400, statusText: 'Bad Request' })

    expect(fixture.componentInstance.logoError()).toBe('format non supporté')
  })

  it('resets the logo and bumps the preview version', () => {
    const { fixture, httpMock } = render()
    const versionBefore = fixture.componentInstance.logoVersion()

    fixture.componentInstance.resetLogo()

    const req = httpMock.expectOne('/api/admin/branding/logo')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)

    expect(fixture.componentInstance.logoVersion()).toBe(versionBefore + 1)
  })

  it('uploads the selected favicon and bumps the preview version on success', () => {
    const { fixture, httpMock } = render()
    selectFile(fixture, 'favicon')
    const versionBefore = fixture.componentInstance.faviconVersion()

    fixture.componentInstance.uploadFavicon()

    httpMock.expectOne('/api/admin/branding/favicon').flush(null)
    expect(fixture.componentInstance.faviconVersion()).toBe(versionBefore + 1)
  })

  it('resets the favicon and bumps the preview version', () => {
    const { fixture, httpMock } = render()
    const versionBefore = fixture.componentInstance.faviconVersion()

    fixture.componentInstance.resetFavicon()

    const req = httpMock.expectOne('/api/admin/branding/favicon')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)

    expect(fixture.componentInstance.faviconVersion()).toBe(versionBefore + 1)
  })

  it('rejects an oversized logo file before any upload, clearing the input', () => {
    const { fixture, httpMock } = render()

    const input = selectOversizedFile(fixture, 'logo')

    expect(fixture.componentInstance.selectedLogoFile()).toBeNull()
    expect(fixture.componentInstance.logoError()).toContain('2 Mo')
    expect(input.value).toBe('')
    httpMock.expectNone('/api/admin/branding/logo')
  })

  it('rejects an oversized favicon file before any upload, clearing the input', () => {
    const { fixture, httpMock } = render()

    const input = selectOversizedFile(fixture, 'favicon')

    expect(fixture.componentInstance.selectedFaviconFile()).toBeNull()
    expect(fixture.componentInstance.faviconError()).toContain('2 Mo')
    expect(input.value).toBe('')
    httpMock.expectNone('/api/admin/branding/favicon')
  })
})
