import { InjectionToken } from '@angular/core'
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

/** Everything the application layer needs from wherever repositories actually live — implemented by an infrastructure adapter, never called directly by a component. */
export interface RepositoryPort {
  list(): Observable<RepositorySummary[]>

  get(id: string): Observable<RepositorySummary>

  create(
    name: string,
    format: RepositoryFormat,
    repoType: RepositoryType,
    remoteUrl: string | null,
    options?: CreateRepositoryOptions,
  ): Observable<RepositorySummary>

  rename(id: string, name: string): Observable<void>

  /** `quotaBytes: null` clears the quota back to unlimited. */
  setQuota(id: string, quotaBytes: number | null): Observable<void>

  /** `keepLastN: null` disables automatic cleanup. */
  setRetentionPolicy(id: string, keepLastN: number | null): Observable<void>

  delete(id: string): Observable<void>

  addGroupMember(groupId: string, memberRepositoryId: string, position: number): Observable<void>

  removeGroupMember(groupId: string, memberId: string): Observable<void>

  packages(id: string): Observable<RepositoryPackages>

  npmPackageDetails(id: string, name: string): Observable<NpmPackageDetails>

  deleteNpmPackage(id: string, name: string): Observable<void>

  deleteNpmPackageVersion(id: string, name: string, version: string): Observable<void>

  npmPackageAudit(id: string, name: string): Observable<NpmAdvisory[]>

  getDependencyAudit(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult | null>

  scanDependencyTree(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult>

  dockerImageDetails(id: string, imageName: string): Observable<DockerImageDetails>

  deleteDockerImage(id: string, imageName: string): Observable<void>

  deleteDockerTag(id: string, imageName: string, tag: string): Observable<void>

  getDockerImageScan(
    id: string,
    imageName: string,
    tag: string,
  ): Observable<DockerImageScanResult | null>

  scanDockerImage(id: string, imageName: string, tag: string): Observable<DockerImageScanResult>
}

export const REPOSITORY_PORT = new InjectionToken<RepositoryPort>('RepositoryPort')
