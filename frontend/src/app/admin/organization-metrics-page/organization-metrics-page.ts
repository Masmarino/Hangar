import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import { Card } from '@masmarino/gabarit'
import { AdminMetricsService } from '../application/metrics.service'
import { AdminStats } from '../domain/metrics.entity'
import { UsageMetrics } from '../usage-metrics/usage-metrics'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'

// Mirrors the super-admin's own split: the three summary cards live here, and per-repository
// usage is the reused UsageMetrics component underneath — both already scoped to the
// caller's own organization server-side, so no organizationId needs threading from the route.
@Component({
  selector: 'app-organization-metrics-page',
  standalone: true,
  imports: [Card, UsageMetrics, OrganizationContextBanner],
  templateUrl: './organization-metrics-page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationMetricsPage {
  private readonly metricsService = inject(AdminMetricsService)

  readonly stats = signal<AdminStats | null>(null)

  constructor() {
    this.metricsService.stats().subscribe((stats) => this.stats.set(stats))
  }
}
