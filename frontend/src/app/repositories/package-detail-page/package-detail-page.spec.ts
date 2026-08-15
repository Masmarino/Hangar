import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router'
import { of } from 'rxjs'
import { PackageDetailPage } from './package-detail-page'
import { PageTitleService } from '../../shell/page-title.service'
import { repositoryProviders } from '../infrastructure/repository.providers'

function render(params: { id?: string; format?: string; name?: string } = {}) {
  const paramMap = convertToParamMap({
    id: params.id ?? 'repo-1',
    format: params.format ?? 'npm',
    name: params.name ?? 'left-pad',
  })
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      ...repositoryProviders,
      {
        provide: ActivatedRoute,
        useValue: { snapshot: { paramMap }, paramMap: of(paramMap) },
      },
    ],
  })
  const fixture = TestBed.createComponent(PackageDetailPage)
  fixture.detectChanges()
  const httpMock = TestBed.inject(HttpTestingController)
  return { fixture, httpMock }
}

// The delete/rescan buttons only render for a viewer with at least `write`
// on the repository — tests exercising those buttons must flush this
// request with a role that grants it.
function flushRepository(httpMock: HttpTestingController, repositoryId: string, myRole = 'write') {
  httpMock.expectOne(`/api/repositories/${repositoryId}`).flush({
    id: repositoryId,
    name: repositoryId,
    format: 'npm',
    repo_type: 'hosted',
    remote_url: null,
    group_members: [],
    my_role: myRole,
  })
}

function flushAudit(
  httpMock: HttpTestingController,
  repositoryId: string,
  name: string,
  advisories: unknown[] = [],
) {
  httpMock
    .expectOne(`/api/repositories/${repositoryId}/packages/npm/${name}/audit`)
    .flush(advisories)
}

function flushDockerScan(
  httpMock: HttpTestingController,
  repositoryId: string,
  imageName: string,
  tag: string,
  result: object | null = null,
) {
  httpMock
    .expectOne(`/api/repositories/${repositoryId}/packages/docker/${imageName}/tags/${tag}/scan`)
    .flush(result)
}

function flushDependencyAudit(
  httpMock: HttpTestingController,
  repositoryId: string,
  name: string,
  version: string,
  result: object | null = null,
) {
  httpMock
    .expectOne(
      `/api/repositories/${repositoryId}/packages/npm/${name}/versions/${version}/dependency-audit`,
    )
    .flush(result)
}

describe('PackageDetailPage', () => {
  it('sets the shared page title to the package name', () => {
    const { httpMock } = render({ name: 'left-pad' })
    const pageTitle = TestBed.inject(PageTitleService)

    expect(pageTitle.title()).toBe('left-pad')

    httpMock
      .expectOne('/api/repositories/repo-1/packages/npm/left-pad')
      .flush({ name: 'left-pad', versions: [], dist_tags: [] })
    flushAudit(httpMock, 'repo-1', 'left-pad')
  })

  it('fetches and renders npm package versions and dist-tags', () => {
    const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
      name: 'left-pad',
      versions: [
        {
          version: '1.1.0',
          published_at: '2026-01-02T00:00:00Z',
          size_bytes: 2048,
          deprecated: true,
          deprecated_message: 'use v2',
          shasum: 'abc',
        },
      ],
      dist_tags: [{ tag: 'latest', version: '1.1.0' }],
    })
    flushAudit(httpMock, 'repo-1', 'left-pad')
    flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.1.0')
    fixture.detectChanges()

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('1.1.0')
    expect(text).toContain('déprécié')
    expect(text).toContain('Ko')
    expect(text).toContain('latest → 1.1.0')
  })

  it('deletes an npm version after confirmation, then refetches', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
      name: 'left-pad',
      versions: [
        {
          version: '1.0.0',
          published_at: '2026-01-01T00:00:00Z',
          size_bytes: 1024,
          deprecated: false,
          deprecated_message: null,
          shasum: 'a',
        },
      ],
      dist_tags: [],
    })
    flushAudit(httpMock, 'repo-1', 'left-pad')
    flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0')
    flushRepository(httpMock, 'repo-1')
    fixture.detectChanges()
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate').mockResolvedValue(true)

    const button: HTMLButtonElement = fixture.nativeElement.querySelector(
      '[data-testid="delete-version-1.0.0"] button',
    )
    button.click()

    expect(window.confirm).toHaveBeenCalled()
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad/versions/1.0.0').flush(null)

    // The delete cascaded (last version gone) — the refetch 404s and the page navigates back.
    httpMock
      .expectOne('/api/repositories/repo-1/packages/npm/left-pad')
      .flush(null, { status: 404, statusText: 'Not Found' })
  })

  it('does not delete when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
      name: 'left-pad',
      versions: [
        {
          version: '1.0.0',
          published_at: '2026-01-01T00:00:00Z',
          size_bytes: 1024,
          deprecated: false,
          deprecated_message: null,
          shasum: 'a',
        },
      ],
      dist_tags: [],
    })
    flushAudit(httpMock, 'repo-1', 'left-pad')
    flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0')
    flushRepository(httpMock, 'repo-1')
    fixture.detectChanges()

    const button: HTMLButtonElement = fixture.nativeElement.querySelector(
      '[data-testid="delete-version-1.0.0"] button',
    )
    button.click()

    httpMock.expectNone('/api/repositories/repo-1/packages/npm/left-pad/versions/1.0.0')
  })

  it('deletes the whole npm package and navigates back to the repository', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = render({ id: 'repo-1', format: 'npm', name: 'left-pad' })
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
      name: 'left-pad',
      versions: [
        {
          version: '1.0.0',
          published_at: '2026-01-01T00:00:00Z',
          size_bytes: 1024,
          deprecated: false,
          deprecated_message: null,
          shasum: 'a',
        },
      ],
      dist_tags: [],
    })
    flushAudit(httpMock, 'repo-1', 'left-pad')
    flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0')
    flushRepository(httpMock, 'repo-1')
    fixture.detectChanges()
    const router = TestBed.inject(Router)
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true)

    const buttons: HTMLButtonElement[] = Array.from(
      fixture.nativeElement.querySelectorAll('gbt-button button'),
    )
    const wholeDeleteButton = buttons.find((b) =>
      b.textContent?.includes('Supprimer tout le package'),
    )!
    wholeDeleteButton.click()

    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush(null)
    expect(navigate).toHaveBeenCalledWith(['/repositories', 'repo-1'])
  })

  it('fetches and renders docker tags with a shortened digest', () => {
    const { fixture, httpMock } = render({ format: 'docker', name: 'my-app' })
    httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app').flush({
      image_name: 'my-app',
      tags: [
        {
          tag: 'latest',
          digest: 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd',
          media_type: 'application/vnd.docker.distribution.manifest.v2+json',
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    })
    flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest')
    fixture.detectChanges()

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('latest')
    expect(text).toContain('sha256:0123456789ab…')
    expect(text).not.toContain('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd')
  })

  it('deletes a docker tag after confirmation and navigates back once no tags remain', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = render({ id: 'repo-1', format: 'docker', name: 'my-app' })
    httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app').flush({
      image_name: 'my-app',
      tags: [
        {
          tag: 'latest',
          digest: 'sha256:aaaa',
          media_type: 'application/vnd.docker.distribution.manifest.v2+json',
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    })
    flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest')
    flushRepository(httpMock, 'repo-1')
    fixture.detectChanges()
    const router = TestBed.inject(Router)
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true)

    const button: HTMLButtonElement = fixture.nativeElement.querySelector(
      '[data-testid="delete-tag-latest"] button',
    )
    button.click()

    httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app/tags/latest').flush(null)
    httpMock
      .expectOne('/api/repositories/repo-1/packages/docker/my-app')
      .flush({ image_name: 'my-app', tags: [] })

    expect(navigate).toHaveBeenCalledWith(['/repositories', 'repo-1'])
  })

  it('links back to the owning repository', () => {
    const { fixture, httpMock } = render({ id: 'repo-1', format: 'npm', name: 'left-pad' })
    const link: HTMLAnchorElement = fixture.nativeElement.querySelector(
      '.package-detail-page__back',
    )

    expect(link.getAttribute('href')).toBe('/repositories/repo-1')

    httpMock
      .expectOne('/api/repositories/repo-1/packages/npm/left-pad')
      .flush({ name: 'left-pad', versions: [], dist_tags: [] })
    flushAudit(httpMock, 'repo-1', 'left-pad')
  })

  describe('security audit', () => {
    function renderWithDetails() {
      const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
      httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
        name: 'left-pad',
        versions: [
          {
            version: '1.0.0',
            published_at: '2026-01-01T00:00:00Z',
            size_bytes: 1024,
            deprecated: false,
            deprecated_message: null,
            shasum: 'a',
          },
        ],
        dist_tags: [],
      })
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0')
      flushRepository(httpMock, 'repo-1')
      return { fixture, httpMock }
    }

    it('shows a loading message while the audit request is pending', () => {
      const { fixture } = renderWithDetails()
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Vérification des vulnérabilités')
    })

    it('shows a reassuring message when no advisories are found', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushAudit(httpMock, 'repo-1', 'left-pad', [])
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Aucune vulnérabilité connue')
    })

    it('lists advisories with their severity and vulnerable version range', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushAudit(httpMock, 'repo-1', 'left-pad', [
        {
          id: 123,
          url: 'https://github.com/advisories/GHSA-xxxx',
          title: 'Prototype Pollution',
          severity: 'critical',
          vulnerable_versions: '<0.2.4',
          cwe: ['CWE-1321'],
          cvss_score: 9.8,
        },
      ])
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain('Prototype Pollution')
      expect(text).toContain('critical')
      expect(text).toContain('<0.2.4')
      expect(text).toContain('CVSS 9.8')
      const link: HTMLAnchorElement = fixture.nativeElement.querySelector(
        '.package-detail__advisory-body a',
      )
      expect(link.getAttribute('href')).toBe('https://github.com/advisories/GHSA-xxxx')
      expect(link.getAttribute('target')).toBe('_blank')
    })

    it('shows a soft failure message without breaking the rest of the page when the audit request errors', () => {
      const { fixture, httpMock } = renderWithDetails()
      httpMock
        .expectOne('/api/repositories/repo-1/packages/npm/left-pad/audit')
        .flush(null, { status: 502, statusText: 'Bad Gateway' })
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain('Impossible de vérifier les vulnérabilités')
      expect(text).toContain('1.0.0')
    })

    it('re-fetches the audit when the rescan button is clicked', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushAudit(httpMock, 'repo-1', 'left-pad', [])
      fixture.detectChanges()

      const buttons: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('gbt-button button'),
      )
      const rescanButton = buttons.find((b) => b.textContent?.includes('Relancer le scan'))!
      rescanButton.click()
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Vérification des vulnérabilités')
      flushAudit(httpMock, 'repo-1', 'left-pad', [
        {
          id: 123,
          url: 'https://github.com/advisories/GHSA-xxxx',
          title: 'Prototype Pollution',
          severity: 'critical',
          vulnerable_versions: '<0.2.4',
          cwe: ['CWE-1321'],
          cvss_score: 9.8,
        },
      ])
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Prototype Pollution')
    })
  })

  describe('dependency audit', () => {
    function renderWithDetails() {
      const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
      httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
        name: 'left-pad',
        versions: [
          {
            version: '1.0.0',
            published_at: '2026-01-01T00:00:00Z',
            size_bytes: 1024,
            deprecated: false,
            deprecated_message: null,
            shasum: 'a',
          },
        ],
        dist_tags: [],
      })
      flushAudit(httpMock, 'repo-1', 'left-pad', [])
      flushRepository(httpMock, 'repo-1')
      return { fixture, httpMock }
    }

    it('prompts to run a scan when none has been recorded yet', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', null)
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Aucune analyse effectuée')
    })

    it('shows the last persisted scan result including findings', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', {
        scanned_at: '2026-01-05T00:00:00Z',
        packages_scanned: 42,
        truncated: false,
        findings: [
          {
            dependency_name: 'minimist',
            dependency_version: '0.0.8',
            advisory: {
              id: 1097677,
              url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h',
              title: 'Prototype Pollution in minimist',
              severity: 'critical',
              vulnerable_versions: '<0.2.4',
              cwe: ['CWE-1321'],
              cvss_score: 9.8,
            },
          },
        ],
      })
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain('42')
      expect(text).toContain('Prototype Pollution in minimist')
      expect(text).toContain('minimist@0.0.8')
    })

    it('shows a truncation notice when the scan hit its cap', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', {
        scanned_at: '2026-01-05T00:00:00Z',
        packages_scanned: 500,
        truncated: true,
        findings: [],
      })
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('analyse partielle')
    })

    it('triggers a fresh scan and shows the new result when the button is clicked', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', null)
      fixture.detectChanges()

      const buttons: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('gbt-button button'),
      )
      const scanButton = buttons.find((b) => b.textContent?.includes('Lancer un scan approfondi'))!
      scanButton.click()
      fixture.detectChanges()

      const req = httpMock.expectOne(
        '/api/repositories/repo-1/packages/npm/left-pad/versions/1.0.0/dependency-audit',
      )
      expect(req.request.method).toBe('POST')
      req.flush({
        scanned_at: '2026-01-06T00:00:00Z',
        packages_scanned: 3,
        truncated: false,
        findings: [],
      })
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain("Aucune vulnérabilité connue dans l'arbre de dépendances")
      expect(text).toContain('3')
    })
  })

  describe('docker image scan', () => {
    function renderWithDetails() {
      const { fixture, httpMock } = render({ format: 'docker', name: 'my-app' })
      httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app').flush({
        image_name: 'my-app',
        tags: [
          {
            tag: 'latest',
            digest: 'sha256:aaaa',
            media_type: 'application/vnd.docker.distribution.manifest.v2+json',
            created_at: '2026-01-01T00:00:00Z',
          },
        ],
      })
      flushRepository(httpMock, 'repo-1')
      return { fixture, httpMock }
    }

    it('prompts to run a scan when none has been recorded yet', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', null)
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Aucun scan effectué')
    })

    it('shows the last persisted scan result including vulnerabilities', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities: [
          {
            id: 'CVE-2022-4450',
            package_name: 'libcrypto1.1',
            installed_version: '1.1.1n-r0',
            fixed_version: '1.1.1t-r0',
            severity: 'HIGH',
            title: 'openssl: double free after calling PEM_read_bio_ex',
            primary_url: 'https://avd.aquasec.com/nvd/cve-2022-4450',
          },
        ],
      })
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain('openssl: double free after calling PEM_read_bio_ex')
      expect(text).toContain('libcrypto1.1@1.1.1n-r0')
      expect(text).toContain('1.1.1t-r0')
      expect(text).toContain('HIGH')
    })

    it('shows a reassuring message when no vulnerabilities are found', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities: [],
      })
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain(
        'Aucune vulnérabilité connue dans cette image',
      )
    })

    it('triggers a fresh scan and shows the new result when the button is clicked', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', null)
      fixture.detectChanges()

      const buttons: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('gbt-button button'),
      )
      const scanButton = buttons.find((b) => b.textContent?.includes('Lancer un scan'))!
      scanButton.click()
      fixture.detectChanges()

      const req = httpMock.expectOne(
        '/api/repositories/repo-1/packages/docker/my-app/tags/latest/scan',
      )
      expect(req.request.method).toBe('POST')
      req.flush({
        scanned_at: '2026-01-06T00:00:00Z',
        vulnerabilities: [],
      })
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain(
        'Aucune vulnérabilité connue dans cette image',
      )
    })

    it('shows a soft failure message without breaking the rest of the page when the scan request errors', () => {
      const { fixture, httpMock } = renderWithDetails()
      httpMock
        .expectOne('/api/repositories/repo-1/packages/docker/my-app/tags/latest/scan')
        .flush(null, { status: 502, statusText: 'Bad Gateway' })
      fixture.detectChanges()

      const text = fixture.nativeElement.textContent as string
      expect(text).toContain("Impossible d'effectuer le scan")
      expect(text).toContain('latest')
    })
  })

  describe('docker vulnerability sorting, pagination and filtering', () => {
    function renderWithDetails() {
      const { fixture, httpMock } = render({ format: 'docker', name: 'my-app' })
      httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app').flush({
        image_name: 'my-app',
        tags: [
          {
            tag: 'latest',
            digest: 'sha256:aaaa',
            media_type: 'application/vnd.docker.distribution.manifest.v2+json',
            created_at: '2026-01-01T00:00:00Z',
          },
        ],
      })
      flushRepository(httpMock, 'repo-1')
      return { fixture, httpMock }
    }

    function vuln(id: string, severity: string) {
      return {
        id,
        package_name: 'pkg',
        installed_version: '1.0.0',
        fixed_version: null,
        severity,
        title: id,
        primary_url: null,
      }
    }

    it('sorts vulnerabilities from most to least critical regardless of scan order', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities: [
          vuln('v-low', 'LOW'),
          vuln('v-critical', 'CRITICAL'),
          vuln('v-high', 'HIGH'),
        ],
      })
      fixture.detectChanges()

      const severityElements: Element[] = Array.from(
        fixture.nativeElement.querySelectorAll('.package-detail__severity'),
      )
      const severities = severityElements.map((el) => el.textContent?.trim())
      expect(severities).toEqual(['CRITICAL', 'HIGH', 'LOW'])
    })

    it('paginates the vulnerability list at 20 per page', () => {
      const { fixture, httpMock } = renderWithDetails()
      const vulnerabilities = Array.from({ length: 25 }, (_, i) => vuln(`v-${i}`, 'LOW'))
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities,
      })
      fixture.detectChanges()

      expect(fixture.nativeElement.querySelectorAll('.package-detail__advisory').length).toBe(20)
      expect(fixture.nativeElement.textContent).toContain('Page 1 sur 2')

      const buttons: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('gbt-button button'),
      )
      buttons.find((b) => b.textContent?.includes('Suivant'))!.click()
      fixture.detectChanges()

      expect(fixture.nativeElement.querySelectorAll('.package-detail__advisory').length).toBe(5)
      expect(fixture.nativeElement.textContent).toContain('Page 2 sur 2')
    })

    it('filtering by severity narrows the list and resets to page 1', () => {
      const { fixture, httpMock } = renderWithDetails()
      const vulnerabilities = [
        ...Array.from({ length: 25 }, (_, i) => vuln(`v-low-${i}`, 'LOW')),
        vuln('v-critical', 'CRITICAL'),
      ]
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities,
      })
      fixture.detectChanges()

      const pageButtons: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('gbt-button button'),
      )
      pageButtons.find((b) => b.textContent?.includes('Suivant'))!.click()
      fixture.detectChanges()
      expect(fixture.nativeElement.textContent).toContain('Page 2 sur 2')

      const filterTrigger: HTMLButtonElement =
        fixture.nativeElement.querySelector('[role="combobox"]')
      filterTrigger.click()
      fixture.detectChanges()
      const options: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('[role="option"]'),
      )
      options.find((o) => o.textContent?.includes('Critique'))!.click()
      fixture.detectChanges()

      expect(fixture.nativeElement.querySelectorAll('.package-detail__advisory').length).toBe(1)
      expect(fixture.nativeElement.textContent).not.toContain('Page 2')
    })

    it('shows a no-match message when the filter matches nothing', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest', {
        scanned_at: '2026-01-05T00:00:00Z',
        vulnerabilities: [vuln('v-low', 'LOW')],
      })
      fixture.detectChanges()

      const filterTrigger: HTMLButtonElement =
        fixture.nativeElement.querySelector('[role="combobox"]')
      filterTrigger.click()
      fixture.detectChanges()
      const options: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('[role="option"]'),
      )
      options.find((o) => o.textContent?.includes('Critique'))!.click()
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain(
        'Aucune vulnérabilité ne correspond aux criticités sélectionnées',
      )
    })
  })

  describe('npm finding sorting and pagination', () => {
    function renderWithDetails() {
      const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
      httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
        name: 'left-pad',
        versions: [
          {
            version: '1.0.0',
            published_at: '2026-01-01T00:00:00Z',
            size_bytes: 1024,
            deprecated: false,
            deprecated_message: null,
            shasum: 'a',
          },
        ],
        dist_tags: [],
      })
      flushAudit(httpMock, 'repo-1', 'left-pad', [])
      flushRepository(httpMock, 'repo-1')
      return { fixture, httpMock }
    }

    function finding(id: number, severity: string) {
      return {
        dependency_name: `dep-${id}`,
        dependency_version: '1.0.0',
        advisory: {
          id,
          url: 'https://example.com',
          title: `advisory-${id}`,
          severity,
          vulnerable_versions: '<1.0.0',
          cwe: [],
          cvss_score: null,
        },
      }
    }

    it('sorts findings from most to least critical', () => {
      const { fixture, httpMock } = renderWithDetails()
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', {
        scanned_at: '2026-01-05T00:00:00Z',
        packages_scanned: 3,
        truncated: false,
        findings: [finding(1, 'low'), finding(2, 'critical'), finding(3, 'high')],
      })
      fixture.detectChanges()

      const severityElements: Element[] = Array.from(
        fixture.nativeElement.querySelectorAll('.package-detail__severity'),
      )
      const severities = severityElements.map((el) => el.textContent?.trim())
      expect(severities).toEqual(['critical', 'high', 'low'])
    })

    it('paginates the findings list at 20 per page', () => {
      const { fixture, httpMock } = renderWithDetails()
      const findings = Array.from({ length: 22 }, (_, i) => finding(i, 'low'))
      flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0', {
        scanned_at: '2026-01-05T00:00:00Z',
        packages_scanned: 22,
        truncated: false,
        findings,
      })
      fixture.detectChanges()

      expect(fixture.nativeElement.querySelectorAll('.package-detail__advisory').length).toBe(20)
      expect(fixture.nativeElement.textContent).toContain('Page 1 sur 2')
    })
  })

  it('hides delete and rescan actions for a read-only viewer of an npm package', () => {
    const { fixture, httpMock } = render({ format: 'npm', name: 'left-pad' })
    httpMock.expectOne('/api/repositories/repo-1/packages/npm/left-pad').flush({
      name: 'left-pad',
      versions: [
        {
          version: '1.0.0',
          published_at: '2026-01-01T00:00:00Z',
          size_bytes: 1024,
          deprecated: false,
          deprecated_message: null,
          shasum: 'a',
        },
      ],
      dist_tags: [],
    })
    flushAudit(httpMock, 'repo-1', 'left-pad')
    flushDependencyAudit(httpMock, 'repo-1', 'left-pad', '1.0.0')
    flushRepository(httpMock, 'repo-1', 'read')
    fixture.detectChanges()

    expect(fixture.nativeElement.querySelector('[data-testid="delete-version-1.0.0"]')).toBeFalsy()
    const buttons: HTMLButtonElement[] = Array.from(
      fixture.nativeElement.querySelectorAll('gbt-button button'),
    )
    expect(buttons.some((b) => b.textContent?.includes('Supprimer tout le package'))).toBe(false)
    expect(buttons.some((b) => b.textContent?.includes('Relancer le scan'))).toBe(false)
    expect(buttons.some((b) => b.textContent?.includes('Lancer un scan approfondi'))).toBe(false)
  })

  it('hides delete and rescan actions for a read-only viewer of a docker image', () => {
    const { fixture, httpMock } = render({ format: 'docker', name: 'my-app' })
    httpMock.expectOne('/api/repositories/repo-1/packages/docker/my-app').flush({
      image_name: 'my-app',
      tags: [
        {
          tag: 'latest',
          digest: 'sha256:aaaa',
          media_type: 'application/vnd.docker.distribution.manifest.v2+json',
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    })
    flushDockerScan(httpMock, 'repo-1', 'my-app', 'latest')
    flushRepository(httpMock, 'repo-1', 'read')
    fixture.detectChanges()

    expect(fixture.nativeElement.querySelector('[data-testid="delete-tag-latest"]')).toBeFalsy()
    const buttons: HTMLButtonElement[] = Array.from(
      fixture.nativeElement.querySelectorAll('gbt-button button'),
    )
    expect(buttons.some((b) => b.textContent?.includes("Supprimer toute l'image"))).toBe(false)
    expect(buttons.some((b) => b.textContent?.includes('Lancer un scan'))).toBe(false)
  })
})
