export type RepositoryFormat = 'npm' | 'docker'
export type RepositoryType = 'hosted' | 'proxy' | 'group'
export type RepositoryRole = 'read' | 'write' | 'admin'

export interface RepositorySummary {
  id: string
  name: string
  format: RepositoryFormat
  repo_type: RepositoryType
  remote_url: string | null
  /** Whether a remote username/password is configured — never the credentials themselves. */
  remote_credentials_set: boolean
  group_members: string[]
  /** `null` means unlimited. */
  quota_bytes: number | null
  /** `null` means automatic cleanup is disabled. */
  retention_keep_last_n: number | null
  /** The current user's own role on this repository. */
  my_role: RepositoryRole
}

export interface CreateRepositoryOptions {
  remoteUsername?: string | null
  remotePassword?: string | null
  /** For a `group` repository: member repository ids, in resolution order. */
  groupMembers?: string[]
  quotaBytes?: number | null
  retentionKeepLastN?: number | null
}

export interface NpmPackageVersionEntry {
  version: string
  published_at: string
  size_bytes: number
  deprecated: boolean
}

export interface VulnerabilitySummary {
  critical: number
  high: number
  medium: number
  low: number
}

export interface NpmPackageTreeEntry {
  name: string
  versions: NpmPackageVersionEntry[]
  vulnerability_summary: VulnerabilitySummary
}

export interface DockerImageTreeEntry {
  image_name: string
  tags: string[]
  vulnerability_summary: VulnerabilitySummary
}

export type RepositoryPackages =
  | { format: 'npm'; packages: NpmPackageTreeEntry[] }
  | { format: 'docker'; images: DockerImageTreeEntry[] }

export interface NpmVersionDetail {
  version: string
  published_at: string
  size_bytes: number
  deprecated: boolean
  deprecated_message: string | null
  shasum: string
}

export interface NpmDistTagDetail {
  tag: string
  version: string
}

export interface NpmPackageDetails {
  name: string
  versions: NpmVersionDetail[]
  dist_tags: NpmDistTagDetail[]
}

export interface DockerTagDetail {
  tag: string
  digest: string
  media_type: string
  created_at: string
}

export interface DockerImageDetails {
  image_name: string
  tags: DockerTagDetail[]
}

export interface NpmAdvisory {
  id: number
  url: string
  title: string
  severity: string
  vulnerable_versions: string
  cwe: string[]
  cvss_score: number | null
}

export interface NpmDependencyAuditFinding {
  dependency_name: string
  dependency_version: string
  advisory: NpmAdvisory
}

export interface NpmDependencyAuditResult {
  scanned_at: string
  packages_scanned: number
  truncated: boolean
  findings: NpmDependencyAuditFinding[]
}

export interface DockerVulnerability {
  id: string
  package_name: string
  installed_version: string
  fixed_version: string | null
  severity: string
  title: string | null
  primary_url: string | null
}

export interface DockerImageScanResult {
  scanned_at: string
  vulnerabilities: DockerVulnerability[]
}
