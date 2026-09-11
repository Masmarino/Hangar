import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { AuditLog } from './audit-log'
import { adminProviders } from '../infrastructure/admin.providers'

describe('AuditLog', () => {
  it('shows a loading state instead of an empty table while the request is in flight', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Chargement…')

    httpMock.expectOne((r) => r.url === '/api/audit/events').flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')
  })

  it('excludes Security events server-side rather than filtering them client-side', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    const req = httpMock.expectOne((r) => r.url === '/api/audit/events')
    expect(req.request.method).toBe('GET')
    expect(req.request.params.get('exclude_aggregate_type')).toBe('Security')
    // The whole point of the server-side filter: the client must not have to drop rows itself.
    expect(req.request.urlWithParams).toContain('exclude_aggregate_type=Security')

    req.flush([
      {
        aggregate_type: 'Permission',
        aggregate_id: 'repo-1',
        event_type: 'PermissionGranted',
        payload: {},
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: 'user-1',
      },
    ])

    expect(fixture.componentInstance.entries().length).toBe(1)
    expect(fixture.componentInstance.entries()[0].aggregate_type).toBe('Permission')
    httpMock.verify()
  })

  it('does not filter the response client-side, even if a Security event were present', () => {
    // Exclusion is entirely the server's job — guards against a client-side filter creeping in.
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    const req = httpMock.expectOne((r) => r.url === '/api/audit/events')
    req.flush([
      {
        aggregate_type: 'Security',
        aggregate_id: 'security-1',
        event_type: 'LoginFailed',
        payload: {},
        occurred_at: '2026-01-01T00:00:01Z',
        actor_id: null,
      },
      {
        aggregate_type: 'Permission',
        aggregate_id: 'repo-1',
        event_type: 'PermissionGranted',
        payload: {},
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: 'user-1',
      },
    ])

    expect(fixture.componentInstance.entries().length).toBe(2)
    expect(fixture.componentInstance.entries().map((e) => e.aggregate_type)).toEqual([
      'Security',
      'Permission',
    ])
    httpMock.verify()
  })

  it('summarizes entries by aggregate type as a bar chart, most frequent first', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    httpMock
      .expectOne((r) => r.url === '/api/audit/events')
      .flush([
        {
          aggregate_type: 'Permission',
          aggregate_id: 'a',
          event_type: 'PermissionGranted',
          payload: {},
          occurred_at: '2026-01-01T00:00:00Z',
          actor_id: 'user-1',
        },
        {
          aggregate_type: 'Permission',
          aggregate_id: 'b',
          event_type: 'PermissionRevoked',
          payload: {},
          occurred_at: '2026-01-01T00:01:00Z',
          actor_id: 'user-1',
        },
        {
          aggregate_type: 'PackageRepository',
          aggregate_id: 'c',
          event_type: 'RepositoryCreated',
          payload: {},
          occurred_at: '2026-01-01T00:02:00Z',
          actor_id: 'user-1',
        },
      ])
    fixture.detectChanges()

    const labels: (string | undefined)[] = Array.from(
      fixture.nativeElement.querySelectorAll('.gbt-dimension-card__label'),
    ).map((el: unknown) => (el as HTMLElement).childNodes[0]?.textContent?.trim())
    expect(labels).toEqual(['Permission', 'PackageRepository'])
  })

  it('does not render the summary section when there are no entries', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne((r) => r.url === '/api/audit/events').flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Résumé')
  })

  it('downloads a CSV of the currently loaded entries', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined)

    fixture.detectChanges()
    httpMock
      .expectOne((r) => r.url === '/api/audit/events')
      .flush([
        {
          aggregate_type: 'Permission',
          aggregate_id: 'repo-1',
          event_type: 'PermissionGranted',
          payload: { role: 'write' },
          occurred_at: '2026-01-01T00:00:00Z',
          actor_id: 'user-1',
        },
      ])

    fixture.componentInstance.downloadCsv()

    expect(createObjectURL).toHaveBeenCalled()
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(blob.type).toContain('text/csv')
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock')
  })

  it('disables the CSV download button when there are no entries', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne((r) => r.url === '/api/audit/events').flush([])
    fixture.detectChanges()

    const button: HTMLButtonElement = fixture.nativeElement.querySelector('gbt-button button')
    expect(button.disabled).toBe(true)
  })

  it('re-fetches when organizationId changes to a different organization — the component is reused, not recreated, across a super-admin switching organizations', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(AuditLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock
      .expectOne((r) => r.url === '/api/audit/events' && !r.params.has('organization_id'))
      .flush([])

    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
    httpMock
      .expectOne((r) => r.params.get('organization_id') === 'org-1')
      .flush([
        {
          aggregate_type: 'Repository',
          aggregate_id: 'r1',
          event_type: 'Created',
          payload: {},
          occurred_at: '2026-01-01T00:00:00Z',
          actor_id: null,
        },
      ])
    fixture.detectChanges()
    expect(fixture.nativeElement.textContent).toContain('Repository')

    fixture.componentRef.setInput('organizationId', 'org-2')
    fixture.detectChanges()
    httpMock.expectOne((r) => r.params.get('organization_id') === 'org-2').flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Repository')
  })
})
