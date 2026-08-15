import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { AdminMetricsService } from '../application/metrics.service'
import { HealthStatus } from '../domain/metrics.entity'
import { Card, GaugeBar } from '@masmarino/gabarit'
import { formatBytes } from '../../shared/format'
import { FormatBytesPipe } from '../../shared/format-bytes.pipe'

@Component({
  selector: 'app-health-status',
  standalone: true,
  imports: [Card, GaugeBar, FormatBytesPipe],
  templateUrl: './health-status.html',
  styleUrl: './health-status.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HealthStatusPage implements OnInit {
  private readonly metricsService = inject(AdminMetricsService)

  readonly status = signal<HealthStatus | null>(null)

  ngOnInit(): void {
    this.metricsService.health().subscribe((status) => this.status.set(status))
  }

  readonly formatByteRatio = (value: number, max: number): string =>
    `${formatBytes(value)} / ${formatBytes(max)}`

  readonly formatRatio = (value: number, max: number): string => `${value} / ${max}`

  formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    const parts: string[] = []
    if (days > 0) {
      parts.push(`${days} j`)
    }
    if (days > 0 || hours > 0) {
      parts.push(`${hours} h`)
    }
    parts.push(`${minutes} min`)
    return parts.join(' ')
  }
}
