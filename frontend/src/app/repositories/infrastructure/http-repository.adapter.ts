import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  CreateRepositoryOptions,
  DockerImageDetails,
  DockerImageScanResult,
  NpmAdvisory,
  NpmDependencyAuditResult,
  NpmPackageDetails,
  RepositoryFormat,
  RepositoryPackages,
  RepositorySummary,
  RepositoryType,
} from '../domain/repository.entity'
import { RepositoryPort } from '../application/repository.port'

@Injectable()
export class HttpRepositoryAdapter implements RepositoryPort {
  private readonly http = inject(HttpClient)

  list(): Observable<RepositorySummary[]> {
    return this.http.get<RepositorySummary[]>('/api/repositories')
  }

  get(id: string): Observable<RepositorySummary> {
    return this.http.get<RepositorySummary>(`/api/repositories/${id}`)
  }

  create(
    name: string,
    format: RepositoryFormat,
    repoType: RepositoryType,
    remoteUrl: string | null,
    options: CreateRepositoryOptions = {},
  ): Observable<RepositorySummary> {
    return this.http.post<RepositorySummary>('/api/repositories', {
      name,
      format,
      repo_type: repoType,
      remote_url: remoteUrl,
      remote_username: options.remoteUsername ?? null,
      remote_password: options.remotePassword ?? null,
      group_members: options.groupMembers ?? [],
      quota_bytes: options.quotaBytes ?? null,
      retention_keep_last_n: options.retentionKeepLastN ?? null,
    })
  }

  rename(id: string, name: string): Observable<void> {
    return this.http.patch<void>(`/api/repositories/${id}`, { name })
  }

  setQuota(id: string, quotaBytes: number | null): Observable<void> {
    return this.http.put<void>(`/api/repositories/${id}/quota`, { quota_bytes: quotaBytes })
  }

  setRetentionPolicy(id: string, keepLastN: number | null): Observable<void> {
    return this.http.put<void>(`/api/repositories/${id}/retention`, {
      keep_last_n_versions: keepLastN,
    })
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(`/api/repositories/${id}`)
  }

  addGroupMember(groupId: string, memberRepositoryId: string, position: number): Observable<void> {
    return this.http.post<void>(`/api/repositories/${groupId}/group-members`, {
      member_repository_id: memberRepositoryId,
      position,
    })
  }

  removeGroupMember(groupId: string, memberId: string): Observable<void> {
    return this.http.delete<void>(`/api/repositories/${groupId}/group-members/${memberId}`)
  }

  packages(id: string): Observable<RepositoryPackages> {
    return this.http.get<RepositoryPackages>(`/api/repositories/${id}/packages`)
  }

  npmPackageDetails(id: string, name: string): Observable<NpmPackageDetails> {
    return this.http.get<NpmPackageDetails>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}`,
    )
  }

  deleteNpmPackage(id: string, name: string): Observable<void> {
    return this.http.delete<void>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}`,
    )
  }

  deleteNpmPackageVersion(id: string, name: string, version: string): Observable<void> {
    return this.http.delete<void>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
    )
  }

  npmPackageAudit(id: string, name: string): Observable<NpmAdvisory[]> {
    return this.http.get<NpmAdvisory[]>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}/audit`,
    )
  }

  getDependencyAudit(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult | null> {
    return this.http.get<NpmDependencyAuditResult | null>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}/dependency-audit`,
    )
  }

  scanDependencyTree(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult> {
    return this.http.post<NpmDependencyAuditResult>(
      `/api/repositories/${id}/packages/npm/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}/dependency-audit`,
      {},
    )
  }

  dockerImageDetails(id: string, imageName: string): Observable<DockerImageDetails> {
    return this.http.get<DockerImageDetails>(
      `/api/repositories/${id}/packages/docker/${encodeURIComponent(imageName)}`,
    )
  }

  deleteDockerImage(id: string, imageName: string): Observable<void> {
    return this.http.delete<void>(
      `/api/repositories/${id}/packages/docker/${encodeURIComponent(imageName)}`,
    )
  }

  deleteDockerTag(id: string, imageName: string, tag: string): Observable<void> {
    return this.http.delete<void>(
      `/api/repositories/${id}/packages/docker/${encodeURIComponent(imageName)}/tags/${encodeURIComponent(tag)}`,
    )
  }

  getDockerImageScan(
    id: string,
    imageName: string,
    tag: string,
  ): Observable<DockerImageScanResult | null> {
    return this.http.get<DockerImageScanResult | null>(
      `/api/repositories/${id}/packages/docker/${encodeURIComponent(imageName)}/tags/${encodeURIComponent(tag)}/scan`,
    )
  }

  scanDockerImage(id: string, imageName: string, tag: string): Observable<DockerImageScanResult> {
    return this.http.post<DockerImageScanResult>(
      `/api/repositories/${id}/packages/docker/${encodeURIComponent(imageName)}/tags/${encodeURIComponent(tag)}/scan`,
      {},
    )
  }
}
