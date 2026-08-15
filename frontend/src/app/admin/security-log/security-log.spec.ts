import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { SecurityLog } from './security-log'
import { userProviders } from '../../users/infrastructure/user.providers'
import { repositoryProviders } from '../../repositories/infrastructure/repository.providers'
import { adminProviders } from '../infrastructure/admin.providers'
import { organizationMembersProviders } from '../infrastructure/organization-members.providers'

describe('SecurityLog', () => {
  function render(entries: unknown[] = [], blocked: unknown[] = []) {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...userProviders,
        ...repositoryProviders,
        ...adminProviders,
        ...organizationMembersProviders,
      ],
    })
    const fixture = TestBed.createComponent(SecurityLog)
    const httpMock = TestBed.inject(HttpTestingController)
    fixture.detectChanges()
    httpMock.expectOne((r) => r.url === '/api/audit/events').flush(entries)
    httpMock
      .expectOne('/api/users')
      .flush([{ id: 'user-1', username: 'florian', is_super_admin: true }])
    httpMock.expectOne('/api/repositories').flush([
      {
        id: 'repo-1',
        name: 'my-repo',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
    ])
    httpMock.expectOne('/api/admin/security/blocked').flush(blocked)
    fixture.detectChanges()
    return fixture
  }

  it('shows a loading state instead of an empty table while the request is in flight', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...userProviders,
        ...repositoryProviders,
        ...adminProviders,
        ...organizationMembersProviders,
      ],
    })
    const fixture = TestBed.createComponent(SecurityLog)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Chargement…')

    httpMock.expectOne((r) => r.url === '/api/audit/events').flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')

    // Drain the remaining requests this component fires on init so later
    // tests in this file don't inherit an unflushed backlog.
    httpMock.expectOne('/api/users').flush([])
    httpMock.expectOne('/api/repositories').flush([])
    httpMock.expectOne('/api/admin/security/blocked').flush([])
  })

  it('shows the IP address for a login failure, with the raw username from the payload', () => {
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'x',
        event_type: 'LoginFailed',
        payload: { username: 'attacker', ip: '203.0.113.7' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: null,
      },
    ])

    expect(fixture.componentInstance.rows()).toEqual([
      {
        occurred_at: '2026-01-01T00:00:00Z',
        event_type: 'LoginFailed',
        actor: 'attacker',
        details: 'Depuis 203.0.113.7',
      },
    ])
  })

  it('resolves the actor_id to a username and shows the repository name and action for a denied access', () => {
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'x',
        event_type: 'AccessDenied',
        payload: { user_id: 'user-1', repository_id: 'repo-1', action: 'push' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: 'user-1',
      },
    ])

    expect(fixture.componentInstance.rows()).toEqual([
      {
        occurred_at: '2026-01-01T00:00:00Z',
        event_type: 'AccessDenied',
        actor: 'florian',
        details: 'Action « push » refusée sur my-repo',
      },
    ])
  })

  it('falls back to the raw actor_id when the user cannot be resolved', () => {
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'x',
        event_type: 'AccessDenied',
        payload: { user_id: 'ghost', repository_id: 'repo-1', action: 'pull' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: 'ghost',
      },
    ])

    expect(fixture.componentInstance.rows()[0].actor).toBe('ghost')
  })

  it('summarizes the event counts by type', () => {
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'a',
        event_type: 'LoginFailed',
        payload: { username: 'a', ip: '1.1.1.1' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: null,
      },
      {
        aggregate_type: 'Security',
        aggregate_id: 'b',
        event_type: 'LoginFailed',
        payload: { username: 'b', ip: '1.1.1.2' },
        occurred_at: '2026-01-01T00:01:00Z',
        actor_id: null,
      },
      {
        aggregate_type: 'Security',
        aggregate_id: 'c',
        event_type: 'AccessDenied',
        payload: { user_id: 'user-1', repository_id: 'repo-1', action: 'push' },
        occurred_at: '2026-01-01T00:02:00Z',
        actor_id: 'user-1',
      },
    ])

    expect(fixture.componentInstance.summary()).toEqual(
      expect.arrayContaining([
        { event_type: 'LoginFailed', count: 2 },
        { event_type: 'AccessDenied', count: 1 },
      ]),
    )
  })

  it('renders the summary as a bar chart, most frequent event type first', () => {
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'a',
        event_type: 'LoginFailed',
        payload: { username: 'a', ip: '1.1.1.1' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: null,
      },
      {
        aggregate_type: 'Security',
        aggregate_id: 'b',
        event_type: 'LoginFailed',
        payload: { username: 'b', ip: '1.1.1.2' },
        occurred_at: '2026-01-01T00:01:00Z',
        actor_id: null,
      },
      {
        aggregate_type: 'Security',
        aggregate_id: 'c',
        event_type: 'AccessDenied',
        payload: { user_id: 'user-1', repository_id: 'repo-1', action: 'push' },
        occurred_at: '2026-01-01T00:02:00Z',
        actor_id: 'user-1',
      },
    ])

    const labels: (string | undefined)[] = Array.from(
      fixture.nativeElement.querySelectorAll('.gbt-dimension-card__label'),
    ).map((el: unknown) => (el as HTMLElement).childNodes[0]?.textContent?.trim())
    expect(labels).toEqual(['LoginFailed', 'AccessDenied'])
  })

  it('does not render the summary section when there are no events', () => {
    const fixture = render()

    expect(fixture.nativeElement.textContent).not.toContain('Résumé')
  })

  it('shows currently blocked accounts with a human-readable remaining time', () => {
    const fixture = render([], [{ username: 'attacker', remaining_seconds: 125 }])

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('attacker')
    expect(text).toContain('3 minutes')
  })

  it('shows nothing under "Comptes actuellement bloqués" when no account is blocked', () => {
    const fixture = render([], [])

    expect(fixture.nativeElement.textContent).not.toContain('Comptes actuellement bloqués')
  })

  it('formats remaining time under a minute distinctly', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...userProviders,
        ...repositoryProviders,
        ...adminProviders,
        ...organizationMembersProviders,
      ],
    })
    const fixture = TestBed.createComponent(SecurityLog)
    expect(fixture.componentInstance.formatRemainingTime(30)).toBe("moins d'une minute")
    expect(fixture.componentInstance.formatRemainingTime(90)).toBe('2 minutes')
  })

  it('downloads a CSV of the currently loaded rows', () => {
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const fixture = render([
      {
        aggregate_type: 'Security',
        aggregate_id: 'x',
        event_type: 'LoginFailed',
        payload: { username: 'attacker', ip: '203.0.113.7' },
        occurred_at: '2026-01-01T00:00:00Z',
        actor_id: null,
      },
    ])

    fixture.componentInstance.downloadCsv()

    expect(createObjectURL).toHaveBeenCalled()
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(blob.type).toContain('text/csv')
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock')
  })

  it('disables the CSV download button when there are no rows', () => {
    const fixture = render()

    const button: HTMLButtonElement = fixture.nativeElement.querySelector('gbt-button button')
    expect(button.disabled).toBe(true)
  })

  describe('scoped to an organization', () => {
    function renderScoped(entries: unknown[] = []) {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          ...userProviders,
          ...repositoryProviders,
          ...adminProviders,
          ...organizationMembersProviders,
        ],
      })
      const fixture = TestBed.createComponent(SecurityLog)
      fixture.componentRef.setInput('organizationId', 'org-1')
      const httpMock = TestBed.inject(HttpTestingController)
      fixture.detectChanges()
      httpMock.expectOne((r) => r.url === '/api/audit/events').flush(entries)
      httpMock
        .expectOne('/api/organizations/org-1/users')
        .flush([{ id: 'user-1', username: 'florian', email: null, is_organization_admin: true, invitation_pending: false }])
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()
      return { fixture, httpMock }
    }

    it('resolves the actor via the organization members endpoint, not the global user list', () => {
      const { fixture } = renderScoped([
        {
          aggregate_type: 'Security',
          aggregate_id: 'x',
          event_type: 'AccessDenied',
          payload: { user_id: 'user-1', repository_id: 'repo-1', action: 'push' },
          occurred_at: '2026-01-01T00:00:00Z',
          actor_id: 'user-1',
        },
      ])

      expect(fixture.componentInstance.rows()[0].actor).toBe('florian')
    })

    it('does not call the blocked-accounts endpoint or render the blocked-accounts panel', () => {
      const { fixture, httpMock } = renderScoped()

      httpMock.expectNone('/api/admin/security/blocked')
      expect(fixture.nativeElement.textContent).not.toContain('Comptes actuellement bloqués')
    })
  })
})
