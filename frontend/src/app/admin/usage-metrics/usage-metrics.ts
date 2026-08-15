import {
  ChangeDetectionStrategy,
  Component,
  LOCALE_ID,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core'
import { Card, DimensionCard, DimensionRow, GaugeBar, Table, TableColumn } from '@masmarino/gabarit'
import { AdminMetricsService } from '../application/metrics.service'
import { RepositoryUsage } from '../domain/metrics.entity'
import { formatBytes } from '../../shared/format'

// Beyond this many repositories the chart gets unreadable — the longest tail is folded into one "Autres" bar while the table below still lists every repository individually.
const CHART_TOP_N = 15

@Component({
  selector: 'app-usage-metrics',
  standalone: true,
  imports: [Table, DimensionCard, Card, GaugeBar],
  templateUrl: './usage-metrics.html',
  styleUrl: './usage-metrics.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UsageMetrics implements OnInit {
  private readonly metricsService = inject(AdminMetricsService)

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

  // Only repositories with a quota actually set have anything meaningful to
  // show here — an unlimited repository has no threshold to warn about.
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

  ngOnInit(): void {
    this.metricsService.usage().subscribe((usages) => this.usages.set(usages))
  }
}
