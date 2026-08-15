import { ChangeDetectionStrategy, Component, computed, effect, inject, signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute, Router } from '@angular/router'
import { HttpErrorResponse } from '@angular/common/http'
import { FormsModule } from '@angular/forms'
import { catchError, forkJoin, map, of } from 'rxjs'
import { Button, Card, Select, Table, TableColumn } from '@masmarino/gabarit'
import { PermissionRoleEditor } from '../../repositories/permission-role-editor/permission-role-editor'
import { PermissionsService } from '../../repositories/application/permissions.service'
import {
  ROLE_OPTIONS,
  Role,
  UserPermissionEntry,
} from '../../repositories/domain/permission.entity'
import { RepositoriesService } from '../../repositories/application/repositories.service'
import { RepositorySummary } from '../../repositories/domain/repository.entity'
import { PageTitleService } from '../../shell/page-title.service'
import { UsersService } from '../application/users.service'
import { UserSummary } from '../domain/user.entity'
import { formatSelectedCount } from '../../shared/format'
import { MeService } from '../../shell/application/me.service'

@Component({
  selector: 'app-user-detail',
  standalone: true,
  imports: [Table, Button, Select, PermissionRoleEditor, FormsModule, Card],
  templateUrl: './user-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserDetail {
  private readonly route = inject(ActivatedRoute)
  private readonly router = inject(Router)
  private readonly usersService = inject(UsersService)
  private readonly permissionsService = inject(PermissionsService)
  private readonly repositoriesService = inject(RepositoriesService)
  private readonly pageTitle = inject(PageTitleService)
  private readonly me = inject(MeService)

  // reactive, not a one-time route.snapshot read — Angular can reuse this component across
  // two different :id navigations, and a snapshot would keep showing the previous user
  private readonly routeUserId = toSignal(
    this.route.paramMap.pipe(map((params) => params.get('id')!)),
    {
      requireSync: true,
    },
  )
  private userId!: string

  readonly user = signal<UserSummary | null>(null)
  readonly loadError = signal(false)
  readonly selectedCountLabel = formatSelectedCount
  readonly username = computed(() => this.user()?.username ?? '')

  // Granting/revoking super-admin status is not an organization-scoped right.
  readonly isSuperAdminViewer = computed(() => this.me.isSuperAdmin())
  // Hides delete/resend-invitation on a super-admin target — the backend 403s an org admin there.
  readonly canManageTarget = computed(() => this.isSuperAdminViewer() || !this.user()?.is_super_admin)

  constructor() {
    effect(() => this.pageTitle.title.set(this.username()))
    effect(() => {
      this.userId = this.routeUserId()
      this.reload()
      this.repositoriesService
        .list()
        .subscribe((repositories) => this.repositories.set(repositories))
    })
  }
  readonly permissions = signal<UserPermissionEntry[]>([])
  readonly editingPermission = signal<UserPermissionEntry | null>(null)
  readonly superAdminError = signal<string | null>(null)
  readonly settingSuperAdmin = signal(false)
  readonly resendingInvitation = signal(false)
  readonly invitationResent = signal(false)
  readonly resendInvitationError = signal<string | null>(null)

  readonly repositories = signal<RepositorySummary[]>([])
  readonly repositoryOptions = computed(() =>
    this.repositories().map((repo) => ({ value: repo.id, label: repo.name })),
  )
  // Multi-select: grants the same role to several repositories in one action.
  readonly grantRepositoryIds = signal<string[]>([])
  readonly grantRole = signal<Role>('read')
  readonly roleOptions = ROLE_OPTIONS

  readonly permissionColumns: TableColumn<UserPermissionEntry>[] = [
    { key: 'repository_name', label: 'Dépôt' },
    { key: 'format', label: 'Format' },
    { key: 'role', label: 'Rôle' },
  ]
  readonly permissionRowId = (p: UserPermissionEntry): string => p.repository_id

  private reload(): void {
    const requestedId = this.userId
    this.loadError.set(false)
    this.usersService
      .get(requestedId)
      .pipe(
        catchError(() => {
          if (requestedId === this.userId) {
            this.loadError.set(true)
          }
          return of(null)
        }),
      )
      .subscribe((user) => {
        if (requestedId === this.userId) {
          this.user.set(user)
        }
      })
    this.permissionsService.listForUser(requestedId).subscribe((permissions) => {
      if (requestedId === this.userId) {
        this.permissions.set(permissions)
      }
    })
  }

  openRoleEditor(entry: UserPermissionEntry): void {
    this.editingPermission.set(entry)
  }

  closeRoleEditor(): void {
    this.editingPermission.set(null)
  }

  readonly savingRole = signal(false)

  changeRole(role: Role): void {
    const entry = this.editingPermission()
    if (!entry || this.savingRole()) {
      return
    }
    this.savingRole.set(true)
    this.permissionsService.grant(entry.repository_id, this.userId, role).subscribe({
      next: () => {
        this.savingRole.set(false)
        this.editingPermission.set(null)
        this.reload()
      },
      error: () => this.savingRole.set(false),
    })
  }

  revokeFromEditor(): void {
    const entry = this.editingPermission()
    if (!entry || this.savingRole()) {
      return
    }
    this.savingRole.set(true)
    this.permissionsService.revoke(entry.repository_id, this.userId).subscribe({
      next: () => {
        this.savingRole.set(false)
        this.editingPermission.set(null)
        this.reload()
      },
      error: () => this.savingRole.set(false),
    })
  }

  readonly grantError = signal<string | null>(null)

  grantPermission(): void {
    const repositoryIds = this.grantRepositoryIds()
    if (repositoryIds.length === 0) {
      return
    }
    const role = this.grantRole()
    this.grantError.set(null)
    forkJoin(
      repositoryIds.map((id) => this.permissionsService.grant(id, this.userId, role)),
    ).subscribe({
      next: () => {
        this.grantRepositoryIds.set([])
        this.reload()
      },
      error: () => {
        // forkJoin only surfaces the first failure, but earlier grants in the batch may have landed
        this.grantError.set("Échec de l'attribution sur au moins un dépôt.")
        this.reload()
      },
    })
  }

  setSuperAdmin(): void {
    const user = this.user()
    if (!user || this.settingSuperAdmin()) {
      return
    }
    const next = !user.is_super_admin
    const message = next
      ? `Promouvoir "${user.username}" au rang de super-administrateur ?`
      : `Retirer le rang de super-administrateur à "${user.username}" ?`
    if (!confirm(message)) {
      return
    }
    this.superAdminError.set(null)
    this.settingSuperAdmin.set(true)
    this.usersService.setSuperAdmin(user.id, next).subscribe({
      next: () => {
        this.settingSuperAdmin.set(false)
        this.reload()
      },
      error: (err: HttpErrorResponse) => {
        this.settingSuperAdmin.set(false)
        this.superAdminError.set(
          err.status === 409
            ? 'Impossible de rétrograder le dernier super-administrateur.'
            : 'Impossible de modifier le statut super-administrateur.',
        )
      },
    })
  }

  resendInvitation(): void {
    const user = this.user()
    if (!user) {
      return
    }
    this.invitationResent.set(false)
    this.resendInvitationError.set(null)
    this.resendingInvitation.set(true)
    this.usersService.resendInvitation(user.id).subscribe({
      next: () => {
        this.resendingInvitation.set(false)
        this.invitationResent.set(true)
      },
      error: () => {
        this.resendingInvitation.set(false)
        this.resendInvitationError.set(
          "Échec de l'envoi de l'invitation. Vérifiez la configuration du serveur mail.",
        )
      },
    })
  }

  readonly deleteUserError = signal<string | null>(null)

  deleteUser(): void {
    const user = this.user()
    if (!user || !confirm(`Supprimer l'utilisateur "${user.username}" ?`)) {
      return
    }
    this.deleteUserError.set(null)
    this.usersService.delete(user.id).subscribe({
      next: () => this.router.navigate(['/users']),
      error: () => this.deleteUserError.set("Échec de la suppression de l'utilisateur."),
    })
  }
}
