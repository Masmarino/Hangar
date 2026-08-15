import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import {
  AdminStats,
  HealthStatus,
  MetricsSnapshot,
  RepositoryUsage,
} from '../domain/metrics.entity'

export interface MetricsPort {
  usage(): Observable<RepositoryUsage[]>
  health(): Observable<HealthStatus>
  stats(): Observable<AdminStats>
  /** Evolution over time. `days` defaults to 30 server-side. */
  history(days?: number): Observable<MetricsSnapshot[]>
}

export const METRICS_PORT = new InjectionToken<MetricsPort>('MetricsPort')
