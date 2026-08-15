import { Injectable, inject } from '@angular/core'
import { Observable, catchError, shareReplay, tap, throwError } from 'rxjs'
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
import { REPOSITORY_PORT } from './repository.port'

@Injectable({ providedIn: 'root' })
export class RepositoriesService {
  private readonly port = inject(REPOSITORY_PORT)

  private cachedList$: Observable<RepositorySummary[]> | null = null

  // cached across callers, cleared by any mutation below — forceRefresh is for the shell's
  // search, which needs to see writes that could've come from another tab
  list(options?: { forceRefresh?: boolean }): Observable<RepositorySummary[]> {
    if (!this.cachedList$ || options?.forceRefresh) {
      this.cachedList$ = this.port.list().pipe(
        catchError((err: unknown) => {
          this.cachedList$ = null
          return throwError(() => err)
        }),
        shareReplay(1),
      )
    }
    return this.cachedList$
  }

  get(id: string): Observable<RepositorySummary> {
    return this.port.get(id)
  }

  create(
    name: string,
    format: RepositoryFormat,
    repoType: RepositoryType,
    remoteUrl: string | null,
    options: CreateRepositoryOptions = {},
  ): Observable<RepositorySummary> {
    return this.port
      .create(name, format, repoType, remoteUrl, options)
      .pipe(tap(() => (this.cachedList$ = null)))
  }

  rename(id: string, name: string): Observable<void> {
    return this.port.rename(id, name).pipe(tap(() => (this.cachedList$ = null)))
  }

  setQuota(id: string, quotaBytes: number | null): Observable<void> {
    return this.port.setQuota(id, quotaBytes).pipe(tap(() => (this.cachedList$ = null)))
  }

  setRetentionPolicy(id: string, keepLastN: number | null): Observable<void> {
    return this.port.setRetentionPolicy(id, keepLastN).pipe(tap(() => (this.cachedList$ = null)))
  }

  delete(id: string): Observable<void> {
    return this.port.delete(id).pipe(tap(() => (this.cachedList$ = null)))
  }

  addGroupMember(groupId: string, memberRepositoryId: string, position: number): Observable<void> {
    return this.port
      .addGroupMember(groupId, memberRepositoryId, position)
      .pipe(tap(() => (this.cachedList$ = null)))
  }

  removeGroupMember(groupId: string, memberId: string): Observable<void> {
    return this.port.removeGroupMember(groupId, memberId).pipe(tap(() => (this.cachedList$ = null)))
  }

  packages(id: string): Observable<RepositoryPackages> {
    return this.port.packages(id)
  }

  npmPackageDetails(id: string, name: string): Observable<NpmPackageDetails> {
    return this.port.npmPackageDetails(id, name)
  }

  deleteNpmPackage(id: string, name: string): Observable<void> {
    return this.port.deleteNpmPackage(id, name)
  }

  deleteNpmPackageVersion(id: string, name: string, version: string): Observable<void> {
    return this.port.deleteNpmPackageVersion(id, name, version)
  }

  npmPackageAudit(id: string, name: string): Observable<NpmAdvisory[]> {
    return this.port.npmPackageAudit(id, name)
  }

  getDependencyAudit(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult | null> {
    return this.port.getDependencyAudit(id, name, version)
  }

  scanDependencyTree(
    id: string,
    name: string,
    version: string,
  ): Observable<NpmDependencyAuditResult> {
    return this.port.scanDependencyTree(id, name, version)
  }

  dockerImageDetails(id: string, imageName: string): Observable<DockerImageDetails> {
    return this.port.dockerImageDetails(id, imageName)
  }

  deleteDockerImage(id: string, imageName: string): Observable<void> {
    return this.port.deleteDockerImage(id, imageName)
  }

  deleteDockerTag(id: string, imageName: string, tag: string): Observable<void> {
    return this.port.deleteDockerTag(id, imageName, tag)
  }

  getDockerImageScan(
    id: string,
    imageName: string,
    tag: string,
  ): Observable<DockerImageScanResult | null> {
    return this.port.getDockerImageScan(id, imageName, tag)
  }

  scanDockerImage(id: string, imageName: string, tag: string): Observable<DockerImageScanResult> {
    return this.port.scanDockerImage(id, imageName, tag)
  }
}
