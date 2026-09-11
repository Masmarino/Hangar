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

function orgParams(organizationId?: string): Record<string, string> {
  return organizationId ? { organization_id: organizationId } : {}
}

@Injectable()
export class HttpMetricsAdapter implements MetricsPort {
  private readonly http = inject(HttpClient)

  usage(organizationId?: string): Observable<RepositoryUsage[]> {
    return this.http.get<RepositoryUsage[]>('/api/admin/metrics', {
      params: orgParams(organizationId),
    })
  }

  health(): Observable<HealthStatus> {
    return this.http.get<HealthStatus>('/api/admin/health')
  }

  stats(organizationId?: string): Observable<AdminStats> {
    return this.http.get<AdminStats>('/api/admin/stats', { params: orgParams(organizationId) })
  }

  history(days?: number): Observable<MetricsSnapshot[]> {
    const params: Record<string, number> = days != null ? { days } : {}
    return this.http.get<MetricsSnapshot[]>('/api/admin/metrics/history', { params })
  }
}
