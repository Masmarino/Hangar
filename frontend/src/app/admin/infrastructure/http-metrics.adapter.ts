import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  AdminStats,
  HealthStatus,
  MetricsSnapshot,
  RepositoryUsage,
} from '../domain/metrics.entity'
import { MetricsPort } from '../application/metrics.port'

@Injectable()
export class HttpMetricsAdapter implements MetricsPort {
  private readonly http = inject(HttpClient)

  usage(): Observable<RepositoryUsage[]> {
    return this.http.get<RepositoryUsage[]>('/api/admin/metrics')
  }

  health(): Observable<HealthStatus> {
    return this.http.get<HealthStatus>('/api/admin/health')
  }

  stats(): Observable<AdminStats> {
    return this.http.get<AdminStats>('/api/admin/stats')
  }

  history(days?: number): Observable<MetricsSnapshot[]> {
    const params: Record<string, number> = days != null ? { days } : {}
    return this.http.get<MetricsSnapshot[]>('/api/admin/metrics/history', { params })
  }
}
