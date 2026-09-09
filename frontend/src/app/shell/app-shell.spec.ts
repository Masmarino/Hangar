import { vi } from 'vitest'
import { Component } from '@angular/core'
import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Router, provideRouter } from '@angular/router'
import { provideTransloco } from '@jsverse/transloco'
import { AppShell } from './app-shell'
import { AuthService } from '../auth/application/auth.service'
import { meProviders } from './infrastructure/me.providers'
import { authProviders } from '../auth/infrastructure/auth.providers'
import { userProviders } from '../users/infrastructure/user.providers'
import { repositoryProviders } from '../repositories/infrastructure/repository.providers'

@Component({ standalone: true, template: '' })
class DummyRoutedComponent {}

describe('AppShell', () => {
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AppShell],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...authProviders,
        ...userProviders,
        ...repositoryProviders,
        ...meProviders,
        provideRouter([]),
        provideTransloco({
          config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
        }),
      ],
    })
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  function flushMe(me: {
    id: string
    username: string
    is_super_admin: boolean
    is_organization_admin?: boolean
    organization_id?: string
  }) {
    httpMock
      .expectOne('/api/me')
      .flush({ is_organization_admin: false, organization_id: 'org-1', ...me })
    httpMock.expectOne('/api/repositories').flush([])
    // Both a super-admin and an organization admin can see the "Utilisateurs" search category, so refreshSearchData() fires /api/users for either.
    if (me.is_super_admin || me.is_organization_admin) {
      httpMock.expectOne('/api/users').flush([])
    }
  }

  function setupOnOrganizationRoutes() {
    TestBed.resetTestingModule()
    TestBed.configureTestingModule({
      imports: [AppShell],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...authProviders,
        ...userProviders,
        ...repositoryProviders,
        ...meProviders,
        provideRouter([
          { path: '', component: DummyRoutedComponent },
          { path: 'admin/organizations/:id', component: DummyRoutedComponent },
          { path: 'admin/organizations/:id/audit', component: DummyRoutedComponent },
          { path: 'admin/organizations/:id/metrics', component: DummyRoutedComponent },
        ]),
        provideTransloco({
          config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
        }),
      ],
    })
    httpMock = TestBed.inject(HttpTestingController)
    return TestBed.createComponent(AppShell)
  }

  it('excludes admin-only items from navItems before /api/me resolves', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toEqual(['repositories'])

    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
  })

  it('includes admin-only items in navItems once /api/me resolves with is_super_admin: true', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()

    flushMe({ id: 'user-1', username: 'florian', is_super_admin: true })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toEqual(['repositories', 'users', 'admin'])

    const adminItem = fixture.componentInstance.navItems().find((item) => item.action === 'admin')!
    expect(adminItem.children?.map((child) => child.action)).toEqual([
      'settings',
      'smtp',
      'branding',
      'tokens',
      'export',
      'audit',
      'metrics',
      'security',
      'health',
      'organizations',
    ])
  })

  it('keeps admin-only items hidden when /api/me resolves with is_super_admin: false', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()

    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toEqual(['repositories'])
  })

  it('shows the Utilisateurs item for an organization admin, even though they are not a super-admin', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()

    flushMe({
      id: 'user-1',
      username: 'org-admin',
      is_super_admin: false,
      is_organization_admin: true,
      organization_id: 'org-1',
    })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toContain('users')
  })

  it('shows an Administration submenu for an org-admin who is not a super-admin, linking to their own organization', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({
      id: 'user-1',
      username: 'org-admin',
      is_super_admin: false,
      is_organization_admin: true,
      organization_id: 'org-1',
    })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toEqual(['repositories', 'users', 'organization'])
    const orgItem = fixture.componentInstance
      .navItems()
      .find((item) => item.action === 'organization')!
    expect(orgItem.text).toBe('Administration')
    expect(orgItem.link).toBe('/admin/organizations/org-1')
    expect(orgItem.children?.map((child) => child.action)).toEqual([
      'branding',
      'tokens',
      'audit',
      'security',
      'metrics',
      'settings',
      'smtp',
    ])
    expect(orgItem.children?.map((child) => child.link)).toEqual([
      '/admin/organizations/org-1/branding',
      '/admin/organizations/org-1/tokens',
      '/admin/organizations/org-1/audit',
      '/admin/organizations/org-1/security',
      '/admin/organizations/org-1/metrics',
      '/admin/organizations/org-1/settings',
      '/admin/organizations/org-1/smtp',
    ])
  })

  it('does not show the Administration submenu for a super-admin, who already reaches every organization', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({
      id: 'user-1',
      username: 'admin',
      is_super_admin: true,
      is_organization_admin: true,
      organization_id: 'org-1',
    })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).not.toContain('organization')
  })

  describe('contextual Organisation menu for a super-admin', () => {
    it('is absent while not browsing a specific organization', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
      fixture.detectChanges()

      const actions = fixture.componentInstance.navItems().map((item) => item.action)
      expect(actions).not.toContain('organization')
    })

    it('appears with a Métriques link (among the other org-scoped pages) when browsing that organization', async () => {
      const fixture = setupOnOrganizationRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/organizations/org-1')
      fixture.detectChanges()

      const organizationItem = fixture.componentInstance
        .navItems()
        .find((item) => item.action === 'organization')!
      expect(organizationItem.text).toBe('Organisation')
      expect(organizationItem.link).toBe('/admin/organizations/org-1')
      expect(organizationItem.children?.map((child) => child.action)).toEqual([
        'branding',
        'tokens',
        'audit',
        'security',
        'metrics',
        'settings',
        'smtp',
      ])
      expect(organizationItem.children?.find((child) => child.action === 'metrics')?.link).toBe(
        '/admin/organizations/org-1/metrics',
      )
    })

    it("still appears (and auto-expands) on one of that organization's own sub-pages, e.g. its metrics", async () => {
      const fixture = setupOnOrganizationRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/organizations/org-1/metrics')
      fixture.detectChanges()
      await fixture.whenStable()
      fixture.detectChanges()

      const organizationItem = fixture.componentInstance
        .navItems()
        .find((item) => item.action === 'organization')!
      expect(organizationItem).toBeTruthy()
      expect(fixture.componentInstance.isMenuOpen(organizationItem)).toBe(true)
    })

    it('disappears again once navigation leaves that organization', async () => {
      const fixture = setupOnOrganizationRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/organizations/org-1')
      fixture.detectChanges()
      expect(fixture.componentInstance.navItems().map((item) => item.action)).toContain(
        'organization',
      )

      await router.navigateByUrl('/admin/organizations/org-1/audit')
      await router.navigateByUrl('/')
      fixture.detectChanges()

      expect(fixture.componentInstance.navItems().map((item) => item.action)).not.toContain(
        'organization',
      )
    })
  })

  describe('Administration submenu', () => {
    function setupOnAdminRoutes() {
      TestBed.resetTestingModule()
      TestBed.configureTestingModule({
        imports: [AppShell],
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          ...authProviders,
          ...userProviders,
          ...repositoryProviders,
          ...meProviders,
          provideRouter([
            { path: 'admin', component: DummyRoutedComponent },
            { path: 'admin/audit', component: DummyRoutedComponent },
          ]),
          provideTransloco({
            config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
          }),
        ],
      })
      httpMock = TestBed.inject(HttpTestingController)
      return TestBed.createComponent(AppShell)
    }

    function adminItem(fixture: ReturnType<typeof TestBed.createComponent<AppShell>>) {
      return fixture.componentInstance.navItems().find((item) => item.action === 'admin')!
    }

    it('is collapsed by default and does not render its children', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: true })
      fixture.detectChanges()

      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(false)
      expect(fixture.nativeElement.querySelector('.app-shell__nav-submenu')).toBeFalsy()
    })

    it('opens automatically, marks the child active (not the parent), when landing on a sub-page', async () => {
      const fixture = setupOnAdminRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: true })
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/audit')
      fixture.detectChanges()
      await fixture.whenStable()
      fixture.detectChanges()

      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(true)

      const adminLink: HTMLAnchorElement = fixture.nativeElement.querySelector(
        '.app-shell__nav-group a.app-shell__nav-link',
      )
      const links: HTMLAnchorElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('a.app-shell__nav-link--sub'),
      )
      const auditLink = links.find((el) => el.textContent?.includes('Historique'))!

      expect(adminLink.classList.contains('app-shell__nav-link--active')).toBe(false)
      expect(auditLink).toBeTruthy()
      expect(auditLink.classList.contains('app-shell__nav-link--active')).toBe(true)
      expect(adminLink.getAttribute('aria-current')).toBeNull()
      expect(auditLink.getAttribute('aria-current')).toBe('page')
    })

    it('toggles open and closed via the chevron button, independent of route', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: true })
      fixture.detectChanges()

      const toggle: HTMLButtonElement = fixture.nativeElement.querySelector(
        '.app-shell__nav-group-toggle',
      )
      toggle.click()
      fixture.detectChanges()
      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(true)
      expect(fixture.nativeElement.querySelector('.app-shell__nav-submenu')).toBeTruthy()

      toggle.click()
      fixture.detectChanges()
      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(false)
      expect(fixture.nativeElement.querySelector('.app-shell__nav-submenu')).toBeFalsy()
    })

    it('can be manually collapsed even while on one of its own sub-pages', async () => {
      const fixture = setupOnAdminRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: true })
      fixture.detectChanges()
      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/audit')
      fixture.detectChanges()
      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(true)

      fixture.nativeElement.querySelector('.app-shell__nav-group-toggle').click()
      fixture.detectChanges()

      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(false)
    })

    it('toggling one dropdown group does not affect another open at the same time', async () => {
      const fixture = setupOnOrganizationRoutes()
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      await router.navigateByUrl('/admin/organizations/org-1/audit')
      fixture.detectChanges()
      await fixture.whenStable()
      fixture.detectChanges()

      const organizationItem = fixture.componentInstance
        .navItems()
        .find((item) => item.action === 'organization')!
      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(true)
      expect(fixture.componentInstance.isMenuOpen(organizationItem)).toBe(true)

      const toggles: HTMLButtonElement[] = Array.from(
        fixture.nativeElement.querySelectorAll('.app-shell__nav-group-toggle'),
      )
      toggles[0].click()
      fixture.detectChanges()

      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(false)
      expect(fixture.componentInstance.isMenuOpen(organizationItem)).toBe(true)
    })
  })

  describe('page title', () => {
    function setupWithTitledRoutes() {
      TestBed.resetTestingModule()
      TestBed.configureTestingModule({
        imports: [AppShell],
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          ...authProviders,
          ...userProviders,
          ...repositoryProviders,
          ...meProviders,
          provideRouter([
            { path: 'repositories', component: DummyRoutedComponent, data: { title: 'Dépôts' } },
            { path: 'admin', component: DummyRoutedComponent, data: { title: 'Administration' } },
          ]),
          provideTransloco({
            config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
          }),
        ],
      })
      httpMock = TestBed.inject(HttpTestingController)
      return TestBed.createComponent(AppShell)
    }

    it("reads the initial route's static title on first render", async () => {
      const fixture = setupWithTitledRoutes()
      const router = TestBed.inject(Router)
      await router.navigateByUrl('/repositories')
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
      fixture.detectChanges()

      expect(fixture.componentInstance.pageTitle.title()).toBe('Dépôts')
      expect(fixture.nativeElement.querySelector('.app-shell__page-title').textContent).toContain(
        'Dépôts',
      )
    })

    it("updates to the new route's title on navigation", async () => {
      const fixture = setupWithTitledRoutes()
      const router = TestBed.inject(Router)
      await router.navigateByUrl('/repositories')
      fixture.detectChanges()
      flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
      fixture.detectChanges()
      expect(fixture.componentInstance.pageTitle.title()).toBe('Dépôts')

      await router.navigateByUrl('/admin')
      fixture.detectChanges()

      expect(fixture.componentInstance.pageTitle.title()).toBe('Administration')
    })
  })

  it('clears the session and routes to /login when logout() is called', () => {
    const auth = TestBed.inject(AuthService)
    const router = TestBed.inject(Router)
    const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
    sessionStorage.setItem('hangar_token', 'a-valid-jwt')
    auth.token.set('a-valid-jwt')

    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })

    fixture.componentInstance.logout()

    expect(auth.token()).toBeNull()
    expect(sessionStorage.getItem('hangar_token')).toBeNull()
    expect(navigate).toHaveBeenCalledWith('/login')
  })

  it('toggles the user menu open and closed when the username is clicked', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    const trigger: HTMLButtonElement = fixture.nativeElement.querySelector(
      '.app-shell__user-trigger',
    )
    trigger.click()
    fixture.detectChanges()
    expect(fixture.nativeElement.querySelector('.app-shell__user-dropdown')).toBeTruthy()

    trigger.click()
    fixture.detectChanges()
    expect(fixture.nativeElement.querySelector('.app-shell__user-dropdown')).toBeFalsy()
  })

  it('closes the user menu when clicking outside it', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    fixture.nativeElement.querySelector('.app-shell__user-trigger').click()
    fixture.detectChanges()
    expect(fixture.componentInstance.userMenuOpen()).toBe(true)

    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    fixture.detectChanges()
    expect(fixture.componentInstance.userMenuOpen()).toBe(false)
  })

  it('closes the user menu on Escape', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    fixture.componentInstance.userMenuOpen.set(true)
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))

    expect(fixture.componentInstance.userMenuOpen()).toBe(false)
  })

  it('the user menu links to /account and closes on click', () => {
    TestBed.resetTestingModule()
    TestBed.configureTestingModule({
      imports: [AppShell],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...authProviders,
        ...userProviders,
        ...repositoryProviders,
        ...meProviders,
        provideRouter([{ path: 'account', component: DummyRoutedComponent }]),
        provideTransloco({
          config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
        }),
      ],
    })
    httpMock = TestBed.inject(HttpTestingController)

    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()
    fixture.componentInstance.userMenuOpen.set(true)
    fixture.detectChanges()

    const accountLink: HTMLAnchorElement = fixture.nativeElement.querySelector(
      '.app-shell__user-dropdown-item[href="/account"]',
    )
    expect(accountLink).toBeTruthy()
    expect(accountLink.textContent).toContain('Mon compte')

    accountLink.click()
    fixture.detectChanges()
    expect(fixture.componentInstance.userMenuOpen()).toBe(false)
  })

  describe('search', () => {
    it('filters repositories (and users, for super-admins) by the typed query', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      httpMock
        .expectOne('/api/me')
        .flush({ id: 'user-1', username: 'florian', is_super_admin: true })
      httpMock.expectOne('/api/repositories').flush([
        {
          id: 'r1',
          name: 'my-repo',
          format: 'npm',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
        {
          id: 'r2',
          name: 'other',
          format: 'docker',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
      ])
      httpMock.expectOne('/api/users').flush([
        { id: 'u1', username: 'my-user', is_super_admin: false },
        { id: 'u2', username: 'someone-else', is_super_admin: false },
      ])
      fixture.detectChanges()

      fixture.componentInstance.onSearchInput('my')
      // Starting a search re-fetches, so the header search never shows stale data.
      httpMock.expectOne('/api/repositories').flush([
        {
          id: 'r1',
          name: 'my-repo',
          format: 'npm',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
      ])
      httpMock
        .expectOne('/api/users')
        .flush([{ id: 'u1', username: 'my-user', is_super_admin: false }])

      const categories = fixture.componentInstance.searchResults()
      expect(categories.find((c) => c.label === 'Dépôts')?.items).toEqual([
        { kind: 'repository', id: 'r1', label: 'my-repo' },
      ])
      expect(categories.find((c) => c.label === 'Utilisateurs')?.items).toEqual([
        { kind: 'user', id: 'u1', label: 'my-user' },
      ])
    })

    it('navigates to the selected result and clears the query', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      httpMock
        .expectOne('/api/me')
        .flush({ id: 'user-1', username: 'florian', is_super_admin: false })
      httpMock.expectOne('/api/repositories').flush([
        {
          id: 'r1',
          name: 'my-repo',
          format: 'npm',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
      ])
      fixture.detectChanges()

      const router = TestBed.inject(Router)
      const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
      fixture.componentInstance.onSearchInput('my')
      httpMock.expectOne('/api/repositories').flush([
        {
          id: 'r1',
          name: 'my-repo',
          format: 'npm',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
      ])
      fixture.componentInstance.onSelectResult({ kind: 'repository', id: 'r1', label: 'my-repo' })

      expect(navigate).toHaveBeenCalledWith('/repositories/r1')
      expect(fixture.componentInstance.searchQuery()).toBe('')
    })

    it('re-fetches repositories when a search starts, so a repo created elsewhere in the session is found', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      httpMock
        .expectOne('/api/me')
        .flush({ id: 'user-1', username: 'florian', is_super_admin: false })
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      fixture.componentInstance.onSearchInput('new')
      httpMock.expectOne('/api/repositories').flush([
        {
          id: 'r1',
          name: 'newly-created',
          format: 'npm',
          repo_type: 'hosted',
          remote_url: null,
          group_members: [],
        },
      ])

      const categories = fixture.componentInstance.searchResults()
      expect(categories.find((c) => c.label === 'Dépôts')?.items).toEqual([
        { kind: 'repository', id: 'r1', label: 'newly-created' },
      ])
    })

    it('does not re-fetch on every keystroke of the same search', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      httpMock
        .expectOne('/api/me')
        .flush({ id: 'user-1', username: 'florian', is_super_admin: false })
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      fixture.componentInstance.onSearchInput('m')
      httpMock.expectOne('/api/repositories').flush([])
      fixture.componentInstance.onSearchInput('my')

      httpMock.verify()
    })

    it('re-fetches again on a new search after the previous one was cleared', () => {
      const fixture = TestBed.createComponent(AppShell)
      fixture.detectChanges()
      httpMock
        .expectOne('/api/me')
        .flush({ id: 'user-1', username: 'florian', is_super_admin: false })
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      fixture.componentInstance.onSearchInput('first')
      httpMock.expectOne('/api/repositories').flush([])
      // clearing must reset the "new search" state, or the next search reuses the cache
      fixture.componentInstance.onSearchInput('')
      fixture.componentInstance.onSearchInput('second')

      httpMock.expectOne('/api/repositories').flush([])
    })
  })

  it('logs out via the user menu\'s "Déconnexion" item', () => {
    const auth = TestBed.inject(AuthService)
    const router = TestBed.inject(Router)
    const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
    sessionStorage.setItem('hangar_token', 'a-valid-jwt')
    auth.token.set('a-valid-jwt')

    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()
    fixture.componentInstance.userMenuOpen.set(true)
    fixture.detectChanges()

    const items: HTMLButtonElement[] = Array.from(
      fixture.nativeElement.querySelectorAll('button.app-shell__user-dropdown-item'),
    )
    const logoutItem = items.find((el) => el.textContent?.includes('Déconnexion'))!
    logoutItem.click()

    expect(auth.token()).toBeNull()
    expect(navigate).toHaveBeenCalledWith('/login')
    expect(fixture.componentInstance.userMenuOpen()).toBe(false)
  })
})
