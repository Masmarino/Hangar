import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { provideRouter } from '@angular/router'
import { PackageTree } from './package-tree'
import { repositoryProviders } from '../infrastructure/repository.providers'

function render(repositoryId: string) {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      ...repositoryProviders,
    ],
  })
  const fixture = TestBed.createComponent(PackageTree)
  fixture.componentRef.setInput('repositoryId', repositoryId)
  fixture.detectChanges()
  const httpMock = TestBed.inject(HttpTestingController)
  return { fixture, httpMock }
}

describe('PackageTree', () => {
  it('fetches the tree for the given repository id', () => {
    const { httpMock } = render('repo-1')

    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })
  })

  it('shows an empty state when an npm repository has no packages', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Aucun package publié.')
  })

  it('shows an empty state when a docker repository has no images', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'docker', images: [] })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Aucune image publiée.')
  })

  it('lists npm packages with their version count', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({
      format: 'npm',
      packages: [
        {
          name: 'left-pad',
          versions: [
            {
              version: '1.0.0',
              published_at: '2026-01-01T00:00:00Z',
              size_bytes: 10,
              deprecated: false,
            },
          ],
        },
      ],
    })
    fixture.detectChanges()

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('left-pad')
    expect(text).toContain('1')
  })

  it('links a plain npm package name to its detail page', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({
      format: 'npm',
      packages: [
        {
          name: 'left-pad',
          versions: [
            {
              version: '1.0.0',
              published_at: '2026-01-01T00:00:00Z',
              size_bytes: 10,
              deprecated: false,
            },
          ],
        },
      ],
    })
    fixture.detectChanges()

    const link: HTMLAnchorElement = fixture.nativeElement.querySelector('.package-tree__node')
    expect(link.getAttribute('href')).toBe('/repositories/repo-1/packages/npm/left-pad')
  })

  it('percent-encodes a scoped npm package name so it stays a single route segment', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({
      format: 'npm',
      packages: [
        {
          name: '@scope/name',
          versions: [
            {
              version: '1.0.0',
              published_at: '2026-01-01T00:00:00Z',
              size_bytes: 10,
              deprecated: false,
            },
          ],
        },
      ],
    })
    fixture.detectChanges()

    const link: HTMLAnchorElement = fixture.nativeElement.querySelector('.package-tree__node')
    expect(link.getAttribute('href')).toBe('/repositories/repo-1/packages/npm/@scope%2Fname')
  })

  it('links a docker image to its detail page', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({
      format: 'docker',
      images: [{ image_name: 'my-app', tags: ['latest'] }],
    })
    fixture.detectChanges()

    const link: HTMLAnchorElement = fixture.nativeElement.querySelector('.package-tree__node')
    expect(link.getAttribute('href')).toBe('/repositories/repo-1/packages/docker/my-app')
  })

  it('re-fetches when the repository id input changes', () => {
    const { fixture, httpMock } = render('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentRef.setInput('repositoryId', 'repo-2')
    fixture.detectChanges()

    httpMock.expectOne('/api/repositories/repo-2/packages').flush({ format: 'npm', packages: [] })
  })
})
