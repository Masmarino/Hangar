import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Router, provideRouter } from '@angular/router'
import { By } from '@angular/platform-browser'
import { Select, Table } from '@masmarino/gabarit'
import { UsersList } from './users-list'
import { userProviders } from '../infrastructure/user.providers'
import { organizationsProviders } from '../../admin/infrastructure/organizations.providers'
import { MeService } from '../../shell/application/me.service'

const PUBLIC_ORG = { id: 'org-public', slug: 'public', display_name: 'Public', is_public: true }
const ACME_ORG = { id: 'org-acme', slug: 'acme', display_name: 'Acme Corp', is_public: false }

const PUBLIC_USER = {
  id: 'u1',
  username: 'florian',
  is_super_admin: true,
  organization_id: 'org-public',
  email: null,
  invitation_pending: false,
}
const ACME_USER = {
  id: 'u2',
  username: 'acme-user',
  is_super_admin: false,
  organization_id: 'org-acme',
  email: null,
  invitation_pending: false,
}

describe('UsersList', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  function setup(options?: { isSuperAdmin?: boolean }) {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...userProviders,
        ...organizationsProviders,
        { provide: MeService, useValue: { isSuperAdmin: () => options?.isSuperAdmin ?? true } },
      ],
    })
    const fixture = TestBed.createComponent(UsersList)
    const httpMock = TestBed.inject(HttpTestingController)
    return { fixture, httpMock }
  }

  function flushInitialLoad(
    httpMock: HttpTestingController,
    users: unknown[] = [PUBLIC_USER],
    organizations: unknown[] = [PUBLIC_ORG, ACME_ORG],
  ) {
    httpMock.expectOne('/api/users').flush(users)
    httpMock.expectOne('/api/organizations').flush(organizations)
  }

  it('loads users into the users signal on init', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock)

    expect(fixture.componentInstance.users().length).toBe(1)
  })

  it('shows a loading state instead of an empty table while the request is in flight', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Chargement…')
    expect(fixture.debugElement.query(By.directive(Table))).toBeNull()

    flushInitialLoad(httpMock)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')
    expect(fixture.debugElement.query(By.directive(Table))).toBeTruthy()
  })

  it('navigates to the user detail page when a table row is clicked', () => {
    const { fixture, httpMock } = setup()
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')

    fixture.detectChanges()
    flushInitialLoad(httpMock)
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', PUBLIC_USER)

    expect(router.navigate).toHaveBeenCalledWith(['/users', 'u1'])
  })

  it('shows a retryable error instead of hanging on "Chargement…" when the request fails', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    httpMock.expectOne('/api/users').flush('error', { status: 500, statusText: 'Server Error' })
    httpMock.expectOne('/api/organizations').flush([PUBLIC_ORG])
    fixture.detectChanges()

    expect(fixture.componentInstance.loading()).toBe(false)
    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')
    expect(fixture.componentInstance.error()).not.toBeNull()
  })

  it('defaults the organization filter to the public organization', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock, [PUBLIC_USER, ACME_USER])

    expect(fixture.componentInstance.selectedOrganizationId()).toBe('org-public')
    expect(fixture.componentInstance.filteredUsers()).toEqual([PUBLIC_USER])
  })

  it('shows every user across organizations when "ALL" is selected', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock, [PUBLIC_USER, ACME_USER])
    fixture.componentInstance.selectedOrganizationId.set('ALL')
    fixture.detectChanges()

    expect(fixture.componentInstance.filteredUsers()).toEqual([PUBLIC_USER, ACME_USER])
  })

  it('offers an option per organization plus "Toutes les organisations"', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock)
    fixture.detectChanges()

    expect(fixture.componentInstance.organizationOptions()).toEqual([
      { value: 'ALL', label: 'Toutes les organisations' },
      { value: 'org-public', label: 'Public' },
      { value: 'org-acme', label: 'Acme Corp' },
    ])
  })

  it('renders the organization display name in the table, not the raw id', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock, [PUBLIC_USER, ACME_USER])
    fixture.componentInstance.selectedOrganizationId.set('ALL')
    fixture.detectChanges()

    const organizationColumn = fixture.componentInstance
      .columns()
      .find((c) => c.key === 'organization_id')
    expect(organizationColumn?.format?.(ACME_USER)).toBe('Acme Corp')
  })

  it('keeps the viewer-selected organization filter across a reload triggered by creating a user', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock, [PUBLIC_USER, ACME_USER])
    fixture.componentInstance.selectedOrganizationId.set('ALL')

    // Both services cache their list() — a bare reload() with no intervening mutation
    // replays from cache rather than issuing a second request.
    fixture.componentInstance.reload()

    expect(fixture.componentInstance.selectedOrganizationId()).toBe('ALL')
  })

  it('renders an organization select control', () => {
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    flushInitialLoad(httpMock)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(Select))).toBeTruthy()
  })

  describe('as an organization admin', () => {
    it("loads only its own organization's users, with a single request and no /api/organizations call", () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })

      fixture.detectChanges()
      httpMock.expectOne('/api/users').flush([ACME_USER])
      fixture.detectChanges()

      expect(fixture.componentInstance.users()).toEqual([ACME_USER])
      expect(fixture.componentInstance.filteredUsers()).toEqual([ACME_USER])
      httpMock.verify()
    })

    it('hides the organization filter, the create-user toolbar, and the organization column', () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })

      fixture.detectChanges()
      httpMock.expectOne('/api/users').flush([ACME_USER])
      fixture.detectChanges()

      expect(fixture.debugElement.query(By.directive(Select))).toBeNull()
      expect(fixture.nativeElement.textContent).not.toContain('Nouvel utilisateur')
      expect(fixture.componentInstance.columns().map((c) => c.key)).not.toContain('organization_id')
    })

    it("navigates to the user detail page on row click, same as a super-admin — an organization admin has the same rights over their own organization's users", () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })
      const router = TestBed.inject(Router)
      vi.spyOn(router, 'navigate')

      fixture.detectChanges()
      httpMock.expectOne('/api/users').flush([ACME_USER])
      fixture.detectChanges()

      fixture.componentInstance.openDetail(ACME_USER)

      expect(router.navigate).toHaveBeenCalledWith(['/users', 'u2'])
    })

    it('surfaces a retryable error when the scoped request fails', () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })

      fixture.detectChanges()
      httpMock.expectOne('/api/users').flush('error', { status: 500, statusText: 'Server Error' })
      fixture.detectChanges()

      expect(fixture.componentInstance.loading()).toBe(false)
      expect(fixture.componentInstance.error()).not.toBeNull()
    })
  })
})
