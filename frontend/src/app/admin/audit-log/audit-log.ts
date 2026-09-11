import {
  ChangeDetectionStrategy,
  Component,
  LOCALE_ID,
  computed,
  effect,
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
import { AuditEntry } from '../domain/audit.entity'
import { toCsv } from '../../shared/csv'
import { downloadBlob } from '../../shared/download'

interface AuditCsvRow {
  occurred_at: string
  aggregate_type: string
  aggregate_id: string
  event_type: string
  actor_id: string | null
  payload: string
}

@Component({
  selector: 'app-audit-log',
  standalone: true,
  imports: [Table, DimensionCard, Button, Card],
  providers: [DatePipe],
  templateUrl: './audit-log.html',
  styleUrl: './audit-log.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AuditLog {
  private readonly auditService = inject(AuditService)
  private readonly datePipe = inject(DatePipe)

  /** Set only when embedded in an organization's own admin page — scopes the query to it. */
  readonly organizationId = input<string | undefined>(undefined)

  readonly entries = signal<AuditEntry[]>([])
  readonly loading = signal(true)

  private readonly csvColumns: { key: keyof AuditCsvRow; label: string }[] = [
    { key: 'occurred_at', label: 'Date' },
    { key: 'aggregate_type', label: 'Type' },
    { key: 'aggregate_id', label: 'Identifiant' },
    { key: 'event_type', label: 'Événement' },
    { key: 'actor_id', label: 'Acteur' },
    { key: 'payload', label: 'Détails' },
  ]

  readonly columns: TableColumn<AuditEntry>[] = [
    {
      key: 'occurred_at',
      label: 'Date',
      format: (e) => this.datePipe.transform(e.occurred_at, 'short') ?? '',
    },
    { key: 'aggregate_type', label: 'Type' },
    { key: 'event_type', label: 'Événement' },
    { key: 'actor_id', label: 'Acteur' },
  ]
  readonly rowId = (e: AuditEntry): string => `${e.occurred_at}|${e.aggregate_id}|${e.event_type}`

  readonly locale = inject(LOCALE_ID)

  readonly summaryChartData = computed<DimensionRow[]>(() => {
    const counts = new Map<string, number>()
    for (const entry of this.entries()) {
      counts.set(entry.aggregate_type, (counts.get(entry.aggregate_type) ?? 0) + 1)
    }
    return Array.from(counts.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
  })

  // effect(), not ngOnInit — this component is reused across organizations on the same route.
  constructor() {
    effect(() => {
      const organizationId = this.organizationId()
      this.loading.set(true)
      // Security events have their own screen, excluded server-side.
      this.auditService
        .query({ exclude_aggregate_type: 'Security', organization_id: organizationId })
        .subscribe((entries) => {
          this.entries.set(entries)
          this.loading.set(false)
        })
    })
  }

  /** Exports exactly what's currently loaded on screen — no separate export request. */
  downloadCsv(): void {
    const rows: AuditCsvRow[] = this.entries().map((entry) => ({
      occurred_at: entry.occurred_at,
      aggregate_type: entry.aggregate_type,
      aggregate_id: entry.aggregate_id,
      event_type: entry.event_type,
      actor_id: entry.actor_id,
      payload: JSON.stringify(entry.payload),
    }))
    const csv = toCsv(rows, this.csvColumns)
    downloadBlob(
      new Blob([csv], { type: 'text/csv;charset=utf-8' }),
      `hangar-audit-${new Date().toISOString().slice(0, 10)}.csv`,
    )
  }
}
