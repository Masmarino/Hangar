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
import { Card, DimensionCard, DimensionRow, GaugeBar, Table, TableColumn } from '@masmarino/gabarit'
import { AdminMetricsService } from '../application/metrics.service'
import { RepositoryUsage } from '../domain/metrics.entity'
import { formatBytes } from '../../shared/format'

// Past this many, the tail gets folded into one "Autres" bar — the table below still lists everything.
const CHART_TOP_N = 15

@Component({
  selector: 'app-usage-metrics',
  standalone: true,
  imports: [Table, DimensionCard, Card, GaugeBar],
  templateUrl: './usage-metrics.html',
  styleUrl: './usage-metrics.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UsageMetrics {
  private readonly metricsService = inject(AdminMetricsService)

  /** Set only when embedded in an organization's own admin page — scopes the usage to it. */
  readonly organizationId = input<string | undefined>(undefined)

  readonly locale = inject(LOCALE_ID)

  readonly usages = signal<RepositoryUsage[]>([])
  readonly formatBytes = formatBytes
  readonly quotaFormatter = (value: number, max: number) =>
    `${formatBytes(value)} / ${formatBytes(max)}`

  readonly columns: TableColumn<RepositoryUsage>[] = [
    { key: 'name', label: 'Dépôt' },
    { key: 'used_bytes', label: 'Espace utilisé (octets)' },
  ]
  readonly rowId = (u: RepositoryUsage): string => u.repository_id

  // Unlimited repositories have no threshold to warn about.
  readonly quotasInUse = computed(() => this.usages().filter((u) => u.quota_bytes != null))

  readonly chartData = computed<DimensionRow[]>(() => {
    const sorted = [...this.usages()].sort((a, b) => b.used_bytes - a.used_bytes)
    const top = sorted.slice(0, CHART_TOP_N)
    const rest = sorted.slice(CHART_TOP_N)
    const data = top.map((u) => ({
      label: u.name,
      value: u.used_bytes,
      display: formatBytes(u.used_bytes),
    }))
    if (rest.length > 0) {
      const total = rest.reduce((sum, u) => sum + u.used_bytes, 0)
      data.push({ label: `Autres (${rest.length})`, value: total, display: formatBytes(total) })
    }
    return data
  })

  // effect(), not ngOnInit — this component is reused across organizations on the same route.
  constructor() {
    effect(() => {
      this.metricsService
        .usage(this.organizationId())
        .subscribe((usages) => this.usages.set(usages))
    })
  }
}
