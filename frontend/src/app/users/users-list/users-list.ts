import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core'
import { Router } from '@angular/router'
import { FormsModule } from '@angular/forms'
import { forkJoin } from 'rxjs'
import { Button, Select, SelectOption, Table, TableColumn } from '@masmarino/gabarit'
import { CreateUserModal } from '../create-user-modal/create-user-modal'
import { UsersService } from '../application/users.service'
import { UserSummary } from '../domain/user.entity'
import { OrganizationsService } from '../../admin/application/organizations.service'
import { OrganizationSummary } from '../../admin/domain/organization.entity'
import { MeService } from '../../shell/application/me.service'

/** Not a real organization id — selects the unfiltered view across every organization. */
const ALL_ORGANIZATIONS = 'ALL'

@Component({
  selector: 'app-users-list',
  standalone: true,
  imports: [Table, Button, Select, FormsModule, CreateUserModal],
  templateUrl: './users-list.html',
  styleUrl: './users-list.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UsersList implements OnInit {
  private readonly usersService = inject(UsersService)
  private readonly organizationsService = inject(OrganizationsService)
  private readonly me = inject(MeService)
  private readonly router = inject(Router)

  // Gates the organization filter/column and "Nouvel utilisateur" — an org admin's /api/users
  // is already scoped to their own organization, so those controls would be meaningless for them.
  readonly isSuperAdmin = computed(() => this.me.isSuperAdmin())

  readonly users = signal<UserSummary[]>([])
  readonly organizations = signal<OrganizationSummary[]>([])
  readonly selectedOrganizationId = signal<string>(ALL_ORGANIZATIONS)
  readonly showCreateModal = signal(false)
  readonly loading = signal(true)
  readonly error = signal<string | null>(null)

  private readonly organizationNamesById = computed(
    () => new Map(this.organizations().map((o) => [o.id, o.display_name])),
  )

  readonly organizationOptions = computed<SelectOption<string>[]>(() => [
    { value: ALL_ORGANIZATIONS, label: 'Toutes les organisations' },
    ...this.organizations().map((o) => ({ value: o.id, label: o.display_name })),
  ])

  readonly filteredUsers = computed(() => {
    const organizationId = this.selectedOrganizationId()
    return organizationId === ALL_ORGANIZATIONS
      ? this.users()
      : this.users().filter((u) => u.organization_id === organizationId)
  })

  readonly columns = computed<TableColumn<UserSummary>[]>(() => {
    const columns: TableColumn<UserSummary>[] = [
      { key: 'username', label: "Nom d'utilisateur" },
      { key: 'email', label: 'E-mail' },
    ]
    if (this.isSuperAdmin()) {
      columns.push({
        key: 'organization_id',
        label: 'Organisation',
        format: (u) => this.organizationNamesById().get(u.organization_id) ?? u.organization_id,
      })
    }
    columns.push(
      { key: 'is_super_admin', label: 'Super-admin' },
      { key: 'invitation_pending', label: 'Invitation en attente' },
    )
    return columns
  })
  readonly rowId = (u: UserSummary): string => u.id

  // Set once — a later reload() must not snap the filter back and discard the viewer's pick.
  private hasAppliedDefaultOrganizationFilter = false

  ngOnInit(): void {
    this.reload()
  }

  reload(): void {
    this.error.set(null)
    if (!this.isSuperAdmin()) {
      // Can't call /api/organizations (super-admin only) — no forkJoin needed here.
      this.usersService.list().subscribe({
        next: (users) => {
          this.users.set(users)
          this.loading.set(false)
        },
        error: () => {
          this.loading.set(false)
          this.error.set('Échec du chargement des utilisateurs.')
        },
      })
      return
    }
    forkJoin({
      users: this.usersService.list(),
      organizations: this.organizationsService.list(),
    }).subscribe({
      next: ({ users, organizations }) => {
        this.users.set(users)
        this.organizations.set(organizations)
        if (!this.hasAppliedDefaultOrganizationFilter) {
          // Defaults to the public organization, not every organization at once.
          const publicOrganization = organizations.find((o) => o.is_public)
          this.selectedOrganizationId.set(publicOrganization?.id ?? ALL_ORGANIZATIONS)
          this.hasAppliedDefaultOrganizationFilter = true
        }
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.error.set('Échec du chargement des utilisateurs.')
      },
    })
  }

  onUserCreated(): void {
    this.showCreateModal.set(false)
    this.reload()
  }

  openDetail(user: UserSummary): void {
    // Reachable by whoever reached this list — already scoped by the backend.
    this.router.navigate(['/users', user.id])
  }
}
