import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  HostListener,
  OnInit,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import {
  ActivatedRoute,
  NavigationEnd,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router'
import { filter, map } from 'rxjs'
import { Icon, SearchBar, SearchResultCategory } from '@masmarino/gabarit'
import { AuthService } from '../auth/application/auth.service'
import { MeService } from './application/me.service'
import { PageTitleService } from './page-title.service'
import { RepositoriesService } from '../repositories/application/repositories.service'
import { RepositorySummary } from '../repositories/domain/repository.entity'
import { UsersService } from '../users/application/users.service'
import { UserSummary } from '../users/domain/user.entity'
import { formatResultsAnnouncement } from '../shared/format'

interface NavItem {
  action: string
  icon: string
  text: string
  link: string
  children?: NavItem[]
}

interface SearchResult {
  kind: 'repository' | 'user'
  id: string
  label: string
}

// The instance-wide flat Administration menu is super-admin only.
const SUPER_ADMIN_ONLY_ACTIONS = new Set(['admin'])
// Reachable by a super-admin or an organization admin, never a plain member.
const STAFF_ONLY_ACTIONS = new Set(['users'])

/** The 7 org-scoped admin pages, shared by an org-admin's own menu and a super-admin's contextual one when browsing that organization. */
function organizationAdminChildren(orgLink: string): NavItem[] {
  return [
    { action: 'branding', icon: 'image', text: 'Marque', link: `${orgLink}/branding` },
    { action: 'tokens', icon: 'key', text: 'Jetons API', link: `${orgLink}/tokens` },
    { action: 'audit', icon: 'history', text: 'Historique', link: `${orgLink}/audit` },
    { action: 'security', icon: 'shield', text: 'Sécurité', link: `${orgLink}/security` },
    { action: 'metrics', icon: 'bar-chart', text: 'Métriques', link: `${orgLink}/metrics` },
    { action: 'settings', icon: 'settings', text: 'Paramètres', link: `${orgLink}/settings` },
    { action: 'smtp', icon: 'mail', text: 'Serveur mail', link: `${orgLink}/smtp` },
  ]
}

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, Icon, SearchBar],
  templateUrl: './app-shell.html',
  styleUrl: './app-shell.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AppShell implements OnInit {
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)
  private readonly activatedRoute = inject(ActivatedRoute)
  private readonly repositoriesService = inject(RepositoriesService)
  private readonly usersService = inject(UsersService)
  readonly me = inject(MeService)
  readonly pageTitle = inject(PageTitleService)

  readonly isLoading = signal(true)
  readonly userMenuOpen = signal(false)
  // Per nav-group override — absent here just follows the route (see isMenuOpen).
  private readonly menuManualOverrides = signal<Record<string, boolean>>({})

  private readonly repositories = signal<RepositorySummary[]>([])
  private readonly users = signal<UserSummary[]>([])
  readonly searchQuery = signal('')

  // Whoever can reach /users (STAFF_ONLY_ACTIONS) can also search it.
  private readonly canSeeUsers = computed(
    () => this.me.isSuperAdmin() || this.me.isOrganizationAdmin(),
  )

  readonly searchResults = computed<SearchResultCategory<SearchResult>[]>(() => {
    const query = this.searchQuery().trim().toLowerCase()
    if (!query) {
      return []
    }
    const matchingRepositories: SearchResult[] = this.repositories()
      .filter((repository) => repository.name.toLowerCase().includes(query))
      .map((repository) => ({ kind: 'repository', id: repository.id, label: repository.name }))
    const matchingUsers: SearchResult[] = this.users()
      .filter((user) => user.username.toLowerCase().includes(query))
      .map((user) => ({ kind: 'user', id: user.id, label: user.username }))

    const categories: SearchResultCategory<SearchResult>[] = [
      { label: 'Dépôts', icon: 'package', items: matchingRepositories },
    ]
    if (this.canSeeUsers()) {
      categories.push({ label: 'Utilisateurs', icon: 'user', items: matchingUsers })
    }
    return categories
  })

  readonly searchResultLabel = (item: SearchResult): string => item.label
  readonly resultsAnnouncement = formatResultsAnnouncement

  private readonly userMenu = viewChild<ElementRef<HTMLElement>>('userMenu')

  private readonly currentUrl = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map(() => this.router.url),
    ),
    { initialValue: this.router.url },
  )

  // Drives the contextual "Organisation" nav item when a super-admin is browsing /admin/organizations/:id.
  private readonly browsedOrganizationId = computed(() => {
    const match = this.currentUrl().match(/^\/admin\/organizations\/([^/]+)/)
    return match ? match[1] : null
  })

  // Starts as '' rather than a synchronous deepestRouteTitle() call — the child route
  // hasn't attached to the route tree yet at construction time, and walking it here throws.
  private readonly routeTitle = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map(() => this.deepestRouteTitle()),
    ),
    { initialValue: '' },
  )

  readonly navItems = computed<NavItem[]>(() => {
    const items: NavItem[] = [
      { action: 'repositories', icon: 'package', text: 'Dépôts', link: '/repositories' },
      { action: 'users', icon: 'users', text: 'Utilisateurs', link: '/users' },
      {
        action: 'admin',
        icon: 'layout-dashboard',
        text: 'Administration',
        link: '/admin',
        children: [
          { action: 'settings', icon: 'settings', text: 'Paramètres', link: '/admin/settings' },
          { action: 'smtp', icon: 'mail', text: 'Serveur mail', link: '/admin/smtp' },
          { action: 'branding', icon: 'image', text: 'Marque', link: '/admin/branding' },
          { action: 'tokens', icon: 'key', text: 'Jetons API', link: '/admin/tokens' },
          { action: 'export', icon: 'download', text: 'Export', link: '/admin/export' },
          { action: 'audit', icon: 'history', text: 'Historique', link: '/admin/audit' },
          { action: 'metrics', icon: 'bar-chart', text: 'Métriques', link: '/admin/metrics' },
          { action: 'security', icon: 'shield', text: 'Sécurité', link: '/admin/security' },
          { action: 'health', icon: 'activity', text: 'Santé', link: '/admin/health' },
          {
            action: 'organizations',
            icon: 'server',
            text: 'Organisations',
            link: '/admin/organizations',
          },
        ],
      },
    ]
    if (this.me.isSuperAdmin()) {
      // No standing nav path to an org's own admin pages — only surfaced while browsing that org.
      const browsedOrganizationId = this.browsedOrganizationId()
      if (browsedOrganizationId) {
        const orgLink = `/admin/organizations/${browsedOrganizationId}`
        items.push({
          action: 'organization',
          icon: 'layout-dashboard',
          text: 'Organisation',
          link: orgLink,
          children: organizationAdminChildren(orgLink),
        })
      }
      return items
    }
    let filtered = items.filter((item) => !SUPER_ADMIN_ONLY_ACTIONS.has(item.action))
    if (!this.me.isOrganizationAdmin()) {
      filtered = filtered.filter((item) => !STAFF_ONLY_ACTIONS.has(item.action))
    }
    const organizationId = this.me.organizationId()
    if (this.me.isOrganizationAdmin() && organizationId) {
      const orgLink = `/admin/organizations/${organizationId}`
      filtered.push({
        action: 'organization',
        icon: 'layout-dashboard',
        text: 'Administration',
        link: orgLink,
        children: organizationAdminChildren(orgLink),
      })
    }
    return filtered
  })

  constructor() {
    effect(() => this.pageTitle.title.set(this.routeTitle()))
  }

  ngOnInit(): void {
    this.me.load().subscribe({
      next: () => {
        this.isLoading.set(false)
        this.refreshSearchData()
      },
      error: () => {
        this.isLoading.set(false)
        this.auth.logout()
      },
    })
  }

  // force a refresh when a search starts, since a create/rename/delete elsewhere in the
  // app wouldn't otherwise reach this cache — but not on every keystroke, that'd be overkill
  onSearchInput(query: string): void {
    if (!this.searchQuery() && query) {
      this.refreshSearchData()
    }
    this.searchQuery.set(query)
  }

  private refreshSearchData(): void {
    this.repositoriesService
      .list({ forceRefresh: true })
      .subscribe((repositories) => this.repositories.set(repositories))
    if (this.canSeeUsers()) {
      this.usersService.list({ forceRefresh: true }).subscribe((users) => this.users.set(users))
    }
  }

  onSelectResult(item: SearchResult): void {
    this.searchQuery.set('')
    this.router.navigateByUrl(
      item.kind === 'repository' ? `/repositories/${item.id}` : `/users/${item.id}`,
    )
  }

  private deepestRouteTitle(): string {
    let route = this.activatedRoute
    while (route.firstChild) {
      route = route.firstChild
    }
    return (route.snapshot.data['title'] as string | undefined) ?? ''
  }

  logout(): void {
    this.userMenuOpen.set(false)
    this.auth.logout()
    this.router.navigateByUrl('/login')
  }

  toggleUserMenu(): void {
    this.userMenuOpen.update((open) => !open)
  }

  // Opens automatically while on one of its own pages, until manually toggled.
  isMenuOpen(item: NavItem): boolean {
    return this.menuManualOverrides()[item.action] ?? this.currentUrl().startsWith(item.link)
  }

  toggleMenu(item: NavItem): void {
    this.menuManualOverrides.update((overrides) => ({
      ...overrides,
      [item.action]: !this.isMenuOpen(item),
    }))
  }

  @HostListener('document:click', ['$event'])
  protected onDocumentClick(event: MouseEvent): void {
    const menuEl = this.userMenu()?.nativeElement
    if (this.userMenuOpen() && menuEl && !menuEl.contains(event.target as Node)) {
      this.userMenuOpen.set(false)
    }
  }

  @HostListener('document:keydown.escape')
  protected onEscape(): void {
    this.userMenuOpen.set(false)
  }
}
