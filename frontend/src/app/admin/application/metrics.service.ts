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

  usage(): Observable<RepositoryUsage[]> {
    return this.port.usage()
  }

  health(): Observable<HealthStatus> {
    return this.port.health()
  }

  stats(): Observable<AdminStats> {
    return this.port.stats()
  }

  history(days?: number): Observable<MetricsSnapshot[]> {
    return this.port.history(days)
  }
}
