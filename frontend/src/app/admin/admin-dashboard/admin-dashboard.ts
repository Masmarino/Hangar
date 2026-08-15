import {
  ChangeDetectionStrategy,
  Component,
  LOCALE_ID,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core'
import { DatePipe } from '@angular/common'
import { FormsModule } from '@angular/forms'
import { AdminMetricsService } from '../application/metrics.service'
import { AdminStats, MetricsSnapshot } from '../domain/metrics.entity'
import { AuditService } from '../application/audit.service'
import { AuditEntry } from '../domain/audit.entity'
import { RepositoriesService } from '../../repositories/application/repositories.service'
import { RepositorySummary } from '../../repositories/domain/repository.entity'
import {
  Card,
  type ChartSeries,
  DimensionCard,
  type DimensionRow,
  LineChart,
  Select,
  SelectOption,
} from '@masmarino/gabarit'
import { formatBytes } from '../../shared/format'

const RECENT_ACTIVITY_LIMIT = 10
// Bucket span for the activity chart — long enough to show a trend, short enough that a quiet self-hosted instance doesn't render a wall of empty bars.
const ACTIVITY_CHART_DAYS = 7

const EVOLUTION_DAYS_OPTIONS: SelectOption<number>[] = [
  { value: 1, label: '1 jour' },
  { value: 3, label: '3 jours' },
  { value: 7, label: '7 jours' },
  { value: 30, label: '1 mois' },
]

@Component({
  selector: 'app-admin-dashboard',
  standalone: true,
  imports: [Card, DimensionCard, LineChart, DatePipe, Select, FormsModule],
  templateUrl: './admin-dashboard.html',
  styleUrl: './admin-dashboard.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AdminDashboard implements OnInit {
  private readonly metricsService = inject(AdminMetricsService)
  private readonly auditService = inject(AuditService)
  private readonly repositoriesService = inject(RepositoriesService)

  readonly stats = signal<AdminStats | null>(null)
  readonly recentEvents = signal<AuditEntry[]>([])
  readonly activityEvents = signal<AuditEntry[]>([])
  readonly repositories = signal<RepositorySummary[]>([])
  readonly formatBytes = formatBytes

  readonly evolutionDaysOptions = EVOLUTION_DAYS_OPTIONS

  // Each evolution chart has its own duration control, so each fetches its
  // own history independently rather than the two sharing one window.
  readonly storageEvolutionDays = signal(1)
  readonly countsEvolutionDays = signal(1)
  readonly storageHistory = signal<MetricsSnapshot[]>([])
  readonly countsHistory = signal<MetricsSnapshot[]>([])

  readonly storageEvolutionSeries = computed<ChartSeries<Date>[]>(() => [
    {
      label: 'Stockage',
      points: this.storageHistory().map((h) => ({
        x: new Date(h.recorded_at),
        y: h.total_storage_bytes,
        display: formatBytes(h.total_storage_bytes),
      })),
    },
  ])

  readonly countsEvolutionSeries = computed<ChartSeries<Date>[]>(() => [
    {
      label: 'Utilisateurs',
      points: this.countsHistory().map((h) => ({ x: new Date(h.recorded_at), y: h.total_users })),
    },
    {
      label: 'Dépôts',
      points: this.countsHistory().map((h) => ({
        x: new Date(h.recorded_at),
        y: h.total_repositories,
      })),
    },
  ])

  readonly locale = inject(LOCALE_ID)

  readonly activityChartData = computed<DimensionRow[]>(() => {
    const counts = new Map<string, number>()
    const days: string[] = []
    for (let i = ACTIVITY_CHART_DAYS - 1; i >= 0; i--) {
      const date = new Date()
      date.setUTCDate(date.getUTCDate() - i)
      const key = date.toISOString().slice(0, 10)
      days.push(key)
      counts.set(key, 0)
    }
    for (const event of this.activityEvents()) {
      const key = event.occurred_at.slice(0, 10)
      if (counts.has(key)) {
        counts.set(key, (counts.get(key) ?? 0) + 1)
      }
    }
    return days.map((day) => ({ label: formatDayLabel(day), value: counts.get(day) ?? 0 }))
  })

  readonly repositoriesByFormatChartData = computed<DimensionRow[]>(() => {
    const counts = new Map<string, number>()
    for (const repo of this.repositories()) {
      counts.set(repo.format, (counts.get(repo.format) ?? 0) + 1)
    }
    return Array.from(counts.entries()).map(([label, value]) => ({ label, value }))
  })

  ngOnInit(): void {
    this.metricsService.stats().subscribe((stats) => this.stats.set(stats))

    const from = new Date()
    from.setUTCDate(from.getUTCDate() - (ACTIVITY_CHART_DAYS - 1))
    from.setUTCHours(0, 0, 0, 0)
    this.auditService.query({ from: from.toISOString() }).subscribe((entries) => {
      // Newest-first from the backend, so the same bounded query covers both the chart and the recent list.
      this.activityEvents.set(entries)
      this.recentEvents.set(entries.slice(0, RECENT_ACTIVITY_LIMIT))
    })

    this.repositoriesService.list().subscribe((repos) => this.repositories.set(repos))

    this.loadStorageHistory()
    this.loadCountsHistory()
  }

  setStorageEvolutionDays(days: number): void {
    this.storageEvolutionDays.set(days)
    this.loadStorageHistory()
  }

  setCountsEvolutionDays(days: number): void {
    this.countsEvolutionDays.set(days)
    this.loadCountsHistory()
  }

  private loadStorageHistory(): void {
    const requestedDays = this.storageEvolutionDays()
    this.metricsService.history(requestedDays).subscribe((history) => {
      // A slower, earlier request can resolve after a newer one — only apply the result
      // that's still what's selected.
      if (requestedDays === this.storageEvolutionDays()) {
        this.storageHistory.set(history)
      }
    })
  }

  private loadCountsHistory(): void {
    const requestedDays = this.countsEvolutionDays()
    this.metricsService.history(requestedDays).subscribe((history) => {
      if (requestedDays === this.countsEvolutionDays()) {
        this.countsHistory.set(history)
      }
    })
  }
}

function formatDayLabel(isoDay: string): string {
  const [, month, day] = isoDay.split('-')
  return `${day}/${month}`
}
