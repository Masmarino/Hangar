export interface RepositoryUsage {
  repository_id: string
  name: string
  used_bytes: number
  /** `null` means unlimited. */
  quota_bytes: number | null
}

export interface ComponentHealth {
  status: 'up' | 'down'
  detail: string | null
}

export interface DatabaseHealth extends ComponentHealth {
  response_time_ms: number
  active_connections: number
  max_connections: number
  server_version: string | null
}

export interface StorageHealth extends ComponentHealth {
  used_bytes: number
  free_bytes: number
  total_bytes: number
}

export interface HealthStatus {
  database: DatabaseHealth
  storage: StorageHealth
  uptime_seconds: number
}

export interface AdminStats {
  total_users: number
  total_repositories: number
  total_active_permissions: number
}

export interface MetricsSnapshot {
  recorded_at: string
  total_users: number
  total_repositories: number
  total_storage_bytes: number
}
