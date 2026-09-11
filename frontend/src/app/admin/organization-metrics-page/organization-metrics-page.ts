import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core'
import { Card } from '@masmarino/gabarit'
import { AdminMetricsService } from '../application/metrics.service'
import { AdminStats } from '../domain/metrics.entity'
import { UsageMetrics } from '../usage-metrics/usage-metrics'

@Component({
  selector: 'app-organization-metrics-page',
  standalone: true,
  imports: [Card, UsageMetrics],
  templateUrl: './organization-metrics-page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationMetricsPage {
  private readonly metricsService = inject(AdminMetricsService)

  /** Set only when embedded in an organization's own admin page — scopes the stats to it. */
  readonly organizationId = input<string | undefined>(undefined)

  readonly stats = signal<AdminStats | null>(null)

  // effect(), so it re-fetches — this component is reused across organizations on the same route.
  constructor() {
    effect(() => {
      this.metricsService.stats(this.organizationId()).subscribe((stats) => this.stats.set(stats))
    })
  }
}
