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
import { versionProviders } from './infrastructure/version.providers'
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
        ...versionProviders,
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
    httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
    httpMock
      .expectOne('/api/me')
      .flush({ is_organization_admin: false, organization_id: 'org-1', ...me })
    httpMock.expectOne('/api/repositories').flush([])
    // Both a super-admin and an organization admin can see the "Utilisateurs" search category, so refreshSearchData() fires /api/users for either.
    if (me.is_super_admin || me.is_organization_admin) {
      httpMock.expectOne('/api/users').flush([])
    }
  }

  it('renders a skip-link (from gbt-app-shell) targeting the actual main content element', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    const skipLink: HTMLAnchorElement = fixture.nativeElement.querySelector('.gbt-app-shell__skip')
    expect(skipLink.textContent?.trim()).toBe('Aller au contenu principal')

    const targetId = skipLink.getAttribute('href')!.replace('#', '')
    const main = fixture.nativeElement.querySelector(`#${targetId}`)
    expect(main).toBeTruthy()
    expect(main.classList.contains('gbt-app-shell__content')).toBe(true)
  })

  it('renders the mobile nav toggle (from gbt-app-shell), hidden by default via CSS but present in the DOM', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    const toggle: HTMLButtonElement = fixture.nativeElement.querySelector('.gbt-app-shell__toggle')
    expect(toggle).toBeTruthy()
    expect(toggle.getAttribute('aria-label')).toBe('Ouvrir le menu de navigation')
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
  })

  it('shows the server version in the sidebar once /api/version resolves', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('v0.2.3')

    flushMe({ id: 'user-1', username: 'florian', is_super_admin: false })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('v0.2.3')
  })

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
      'organizations',
      'export',
      'health',
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

  it('shows an Administration link for an org-admin who is not a super-admin, linking to their own organization', () => {
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
    expect(orgItem.children).toBeUndefined()
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

  it('a super-admin never gets a standing "organization" nav item — every organization is reached via the Organisations list instead', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({ id: 'user-1', username: 'admin', is_super_admin: true })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).not.toContain('organization')
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
          ...versionProviders,
          provideRouter([
            { path: 'admin', component: DummyRoutedComponent },
            { path: 'admin/export', component: DummyRoutedComponent },
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
      await router.navigateByUrl('/admin/export')
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
      const exportLink = links.find((el) => el.textContent?.includes('Export'))!

      expect(adminLink.classList.contains('app-shell__nav-link--active')).toBe(false)
      expect(exportLink).toBeTruthy()
      expect(exportLink.classList.contains('app-shell__nav-link--active')).toBe(true)
      expect(adminLink.getAttribute('aria-current')).toBeNull()
      expect(exportLink.getAttribute('aria-current')).toBe('page')
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
      await router.navigateByUrl('/admin/export')
      fixture.detectChanges()
      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(true)

      fixture.nativeElement.querySelector('.app-shell__nav-group-toggle').click()
      fixture.detectChanges()

      expect(fixture.componentInstance.isMenuOpen(adminItem(fixture))).toBe(false)
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
          ...versionProviders,
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
        ...versionProviders,
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
      httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
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
      httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
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
      httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
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
      httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
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
      httpMock.expectOne('/api/version').flush({ version: '0.2.3' })
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
