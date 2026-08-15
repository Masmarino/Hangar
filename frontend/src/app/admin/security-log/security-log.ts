import {
  ChangeDetectionStrategy,
  Component,
  LOCALE_ID,
  OnInit,
  computed,
  inject,
  input,
  signal,
} from '@angular/core'
import { DatePipe } from '@angular/common'
import {
  Button,
  Card,
  DimensionCard,
  type DimensionRow,
  Table,
  TableColumn,
} from '@masmarino/gabarit'
import { AuditService } from '../application/audit.service'
import { AuditEntry, BlockedAccount } from '../domain/audit.entity'
import { UsersService } from '../../users/application/users.service'
import { OrganizationMembersService } from '../application/organization-members.service'
import { RepositoriesService } from '../../repositories/application/repositories.service'
import { toCsv } from '../../shared/csv'
import { downloadBlob } from '../../shared/download'

interface SecurityLogRow {
  occurred_at: string
  event_type: string
  actor: string
  details: string
}

interface EventTypeCount {
  event_type: string
  count: number
}

@Component({
  selector: 'app-security-log',
  standalone: true,
  imports: [Table, DimensionCard, Button, Card],
  providers: [DatePipe],
  templateUrl: './security-log.html',
  styleUrl: './security-log.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SecurityLog implements OnInit {
  private readonly auditService = inject(AuditService)
  private readonly usersService = inject(UsersService)
  private readonly organizationMembersService = inject(OrganizationMembersService)
  private readonly repositoriesService = inject(RepositoriesService)
  private readonly datePipe = inject(DatePipe)

  /** Set only when embedded in an org's own admin page — scopes the view and hides the super-admin-only blocked-accounts panel. */
  readonly organizationId = input<string | undefined>(undefined)

  private readonly entries = signal<AuditEntry[]>([])
  private readonly usernamesById = signal<Map<string, string>>(new Map())
  private readonly repositoryNamesById = signal<Map<string, string>>(new Map())
  readonly blockedAccounts = signal<BlockedAccount[]>([])
  readonly loading = signal(true)

  readonly rows = computed<SecurityLogRow[]>(() =>
    this.entries().map((entry) => ({
      occurred_at: entry.occurred_at,
      event_type: entry.event_type,
      actor: this.actorLabel(entry),
      details: this.detailsLabel(entry),
    })),
  )

  readonly summary = computed<EventTypeCount[]>(() => {
    const counts = new Map<string, number>()
    for (const entry of this.entries()) {
      counts.set(entry.event_type, (counts.get(entry.event_type) ?? 0) + 1)
    }
    return Array.from(counts.entries())
      .map(([event_type, count]) => ({ event_type, count }))
      .sort((a, b) => b.count - a.count)
  })

  readonly locale = inject(LOCALE_ID)

  readonly summaryChartData = computed<DimensionRow[]>(() =>
    this.summary().map((item) => ({ label: item.event_type, value: item.count })),
  )

  readonly blockedAccountRows = computed(() =>
    this.blockedAccounts().map((account) => ({
      username: account.username,
      remaining: this.formatRemainingTime(account.remaining_seconds),
    })),
  )

  readonly columns: TableColumn<SecurityLogRow>[] = [
    {
      key: 'occurred_at',
      label: 'Date',
      format: (r) => this.datePipe.transform(r.occurred_at, 'short') ?? '',
    },
    { key: 'event_type', label: 'Événement' },
    { key: 'actor', label: 'Utilisateur' },
    { key: 'details', label: 'Détails' },
  ]
  readonly rowId = (r: SecurityLogRow): string => `${r.occurred_at}|${r.event_type}|${r.actor}`

  ngOnInit(): void {
    this.auditService.query({ aggregate_type: 'Security' }).subscribe((entries) => {
      this.entries.set(entries)
      this.loading.set(false)
    })
    const organizationId = this.organizationId()
    if (organizationId) {
      this.organizationMembersService
        .list(organizationId)
        .subscribe((members) => this.usernamesById.set(new Map(members.map((m) => [m.id, m.username]))))
    } else {
      this.usersService
        .list()
        .subscribe((users) => this.usernamesById.set(new Map(users.map((u) => [u.id, u.username]))))
      this.auditService.blockedAccounts().subscribe((accounts) => this.blockedAccounts.set(accounts))
    }
    this.repositoriesService
      .list()
      .subscribe((repos) => this.repositoryNamesById.set(new Map(repos.map((r) => [r.id, r.name]))))
  }

  formatRemainingTime(seconds: number): string {
    const minutes = Math.ceil(seconds / 60)
    return minutes <= 1 ? "moins d'une minute" : `${minutes} minutes`
  }

  /** Exports exactly what's currently loaded on screen — no separate export request. */
  downloadCsv(): void {
    const csv = toCsv(this.rows(), this.columns)
    downloadBlob(
      new Blob([csv], { type: 'text/csv;charset=utf-8' }),
      `hangar-security-${new Date().toISOString().slice(0, 10)}.csv`,
    )
  }

  private actorLabel(entry: AuditEntry): string {
    const payload = entry.payload as Record<string, unknown>
    if (typeof payload['username'] === 'string') {
      return payload['username']
    }
    if (entry.actor_id) {
      return this.usernamesById().get(entry.actor_id) ?? entry.actor_id
    }
    return '—'
  }

  private detailsLabel(entry: AuditEntry): string {
    const payload = entry.payload as Record<string, unknown>
    switch (entry.event_type) {
      case 'LoginFailed':
      case 'PasswordChangeFailed':
        return typeof payload['ip'] === 'string' ? `Depuis ${payload['ip']}` : ''
      case 'AccessDenied': {
        const repositoryId = payload['repository_id']
        const repositoryName =
          typeof repositoryId === 'string'
            ? (this.repositoryNamesById().get(repositoryId) ?? repositoryId)
            : '?'
        const action = typeof payload['action'] === 'string' ? payload['action'] : '?'
        return `Action « ${action} » refusée sur ${repositoryName}`
      }
      default:
        return ''
    }
  }
}
