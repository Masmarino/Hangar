import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import {
  AdminStats,
  HealthStatus,
  MetricsSnapshot,
  RepositoryUsage,
} from '../domain/metrics.entity'
import { METRICS_PORT } from './metrics.port'

@Injectable({ providedIn: 'root' })
export class AdminMetricsService {
  private readonly port = inject(METRICS_PORT)

  usage(organizationId?: string): Observable<RepositoryUsage[]> {
    return this.port.usage(organizationId)
  }

  health(): Observable<HealthStatus> {
    return this.port.health()
  }

  stats(organizationId?: string): Observable<AdminStats> {
    return this.port.stats(organizationId)
  }

  history(days?: number): Observable<MetricsSnapshot[]> {
    return this.port.history(days)
  }
}
