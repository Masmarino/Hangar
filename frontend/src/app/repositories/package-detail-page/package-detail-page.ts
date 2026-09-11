import {
  ChangeDetectionStrategy,
  Component,
  Pipe,
  PipeTransform,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute, Router, RouterLink } from '@angular/router'
import { DatePipe } from '@angular/common'
import { FormsModule } from '@angular/forms'
import { map } from 'rxjs'
import { Button, Card, Select, type SelectOption } from '@masmarino/gabarit'
import { RepositoriesService } from '../application/repositories.service'
import {
  DockerImageDetails,
  DockerImageScanResult,
  NpmAdvisory,
  NpmDependencyAuditResult,
  NpmPackageDetails,
  RepositoryFormat,
} from '../domain/repository.entity'
import { PageTitleService } from '../../shell/page-title.service'
import { FormatBytesPipe } from '../../shared/format-bytes.pipe'
import { bySeverityDesc } from '../../shared/severity'
import { formatSelectedCount } from '../../shared/format'
import { ToastService } from '../../shared/toast.service'

const PAGE_SIZE = 20

/** Pure pipe: memoized by Angular per digest, unlike calling a method directly in the template. */
@Pipe({ name: 'shortDigest' })
class ShortDigestPipe implements PipeTransform {
  transform(digest: string): string {
    const [algorithm, hex] = digest.split(':')
    return hex ? `${algorithm}:${hex.slice(0, 12)}…` : digest
  }
}

@Pipe({ name: 'severityClass' })
class SeverityClassPipe implements PipeTransform {
  transform(severity: string): string {
    const normalized = severity.toLowerCase()
    if (normalized === 'critical' || normalized === 'high') {
      return 'package-detail__severity--high'
    }
    if (normalized === 'moderate' || normalized === 'medium') {
      return 'package-detail__severity--moderate'
    }
    return 'package-detail__severity--low'
  }
}

const DOCKER_SEVERITY_OPTIONS: SelectOption<string>[] = [
  { value: 'CRITICAL', label: 'Critique' },
  { value: 'HIGH', label: 'Élevée' },
  { value: 'MEDIUM', label: 'Moyenne' },
  { value: 'LOW', label: 'Faible' },
  { value: 'UNKNOWN', label: 'Inconnue' },
]

const NPM_SEVERITY_OPTIONS: SelectOption<string>[] = [
  { value: 'critical', label: 'Critique' },
  { value: 'high', label: 'Élevée' },
  { value: 'moderate', label: 'Moyenne' },
  { value: 'low', label: 'Faible' },
]

@Component({
  selector: 'app-package-detail-page',
  standalone: true,
  imports: [
    Button,
    DatePipe,
    RouterLink,
    Card,
    Select,
    FormsModule,
    FormatBytesPipe,
    ShortDigestPipe,
    SeverityClassPipe,
  ],
  templateUrl: './package-detail-page.html',
  styleUrl: './package-detail-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PackageDetailPage {
  private readonly route = inject(ActivatedRoute)
  private readonly router = inject(Router)
  private readonly repositoriesService = inject(RepositoriesService)
  private readonly pageTitle = inject(PageTitleService)
  private readonly toastService = inject(ToastService)

  // Reactive, not route.snapshot — Angular reuses this component across param changes.
  private readonly routeParams = toSignal(
    this.route.paramMap.pipe(
      map((params) => ({
        repositoryId: params.get('id')!,
        format: params.get('format') as RepositoryFormat,
        name: params.get('name')!,
      })),
    ),
    { requireSync: true },
  )

  repositoryId!: string
  format!: RepositoryFormat
  name!: string

  readonly selectedCountLabel = formatSelectedCount

  readonly loading = signal(true)
  readonly npmDetails = signal<NpmPackageDetails | null>(null)
  readonly dockerDetails = signal<DockerImageDetails | null>(null)

  // A long publish/tag history renders hundreds of rows otherwise.
  readonly versionsPage = signal(1)
  readonly versionsTotalPages = computed(() =>
    Math.max(1, Math.ceil((this.npmDetails()?.versions.length ?? 0) / PAGE_SIZE)),
  )
  readonly pagedVersions = computed(() => {
    const details = this.npmDetails()
    if (!details) {
      return []
    }
    const page = Math.min(this.versionsPage(), this.versionsTotalPages())
    const start = (page - 1) * PAGE_SIZE
    return details.versions.slice(start, start + PAGE_SIZE)
  })

  readonly tagsPage = signal(1)
  readonly tagsTotalPages = computed(() =>
    Math.max(1, Math.ceil((this.dockerDetails()?.tags.length ?? 0) / PAGE_SIZE)),
  )
  readonly pagedTags = computed(() => {
    const details = this.dockerDetails()
    if (!details) {
      return []
    }
    const page = Math.min(this.tagsPage(), this.tagsTotalPages())
    const start = (page - 1) * PAGE_SIZE
    return details.tags.slice(start, start + PAGE_SIZE)
  })

  // Fetched once on load so delete/rescan buttons can be hidden for a read-only viewer.
  readonly canWrite = signal(false)

  // An outage in npm's advisory database shouldn't block viewing the package.
  readonly auditLoading = signal(true)
  readonly auditAdvisories = signal<NpmAdvisory[] | null>(null)
  readonly auditFailed = signal(false)

  // Reads the last persisted result for `latest` — a fresh scan needs a click.
  readonly depAuditLoading = signal(true)
  readonly depAuditResult = signal<NpmDependencyAuditResult | null>(null)
  readonly depAuditFailed = signal(false)
  readonly depAuditScanning = signal(false)
  readonly depAuditSeverityFilter = signal<string[]>([])
  readonly depAuditPage = signal(1)
  readonly npmSeverityOptions = NPM_SEVERITY_OPTIONS

  readonly sortedFindings = computed(() => {
    const result = this.depAuditResult()
    return result ? [...result.findings].sort(bySeverityDesc((f) => f.advisory.severity)) : []
  })

  readonly filteredFindings = computed(() => {
    const filter = this.depAuditSeverityFilter()
    const all = this.sortedFindings()
    return filter.length === 0 ? all : all.filter((f) => filter.includes(f.advisory.severity))
  })

  readonly depAuditTotalPages = computed(() =>
    Math.max(1, Math.ceil(this.filteredFindings().length / PAGE_SIZE)),
  )

  readonly pagedFindings = computed(() => {
    const page = Math.min(this.depAuditPage(), this.depAuditTotalPages())
    const start = (page - 1) * PAGE_SIZE
    return this.filteredFindings().slice(start, start + PAGE_SIZE)
  })

  // Same as the dependency audit — reads the last completed Trivy scan, not a live one.
  readonly imageScanLoading = signal(true)
  readonly imageScanResult = signal<DockerImageScanResult | null>(null)
  readonly imageScanFailed = signal(false)
  readonly imageScanScanning = signal(false)
  readonly imageScanSeverityFilter = signal<string[]>([])
  readonly imageScanPage = signal(1)
  readonly dockerSeverityOptions = DOCKER_SEVERITY_OPTIONS

  readonly sortedVulnerabilities = computed(() => {
    const result = this.imageScanResult()
    return result ? [...result.vulnerabilities].sort(bySeverityDesc((v) => v.severity)) : []
  })

  readonly filteredVulnerabilities = computed(() => {
    const filter = this.imageScanSeverityFilter()
    const all = this.sortedVulnerabilities()
    return filter.length === 0 ? all : all.filter((v) => filter.includes(v.severity))
  })

  readonly imageScanTotalPages = computed(() =>
    Math.max(1, Math.ceil(this.filteredVulnerabilities().length / PAGE_SIZE)),
  )

  readonly pagedVulnerabilities = computed(() => {
    const page = Math.min(this.imageScanPage(), this.imageScanTotalPages())
    const start = (page - 1) * PAGE_SIZE
    return this.filteredVulnerabilities().slice(start, start + PAGE_SIZE)
  })

  constructor() {
    effect(() => this.pageTitle.title.set(this.routeParams().name))
    effect(() => {
      const params = this.routeParams()
      this.repositoryId = params.repositoryId
      this.format = params.format
      this.name = params.name
      this.reload()
      this.repositoriesService
        .get(this.repositoryId)
        .subscribe((repo) =>
          this.canWrite.set(repo.my_role === 'write' || repo.my_role === 'admin'),
        )
    })
  }

  private reload(): void {
    this.loading.set(true)
    const requested = { repositoryId: this.repositoryId, format: this.format, name: this.name }
    const stillCurrent = () => {
      const current = this.routeParams()
      return (
        current.repositoryId === requested.repositoryId &&
        current.format === requested.format &&
        current.name === requested.name
      )
    }
    if (this.format === 'npm') {
      this.repositoriesService.npmPackageDetails(this.repositoryId, this.name).subscribe({
        next: (details) => {
          if (!stillCurrent()) {
            return
          }
          this.npmDetails.set(details)
          this.versionsPage.set(1)
          this.loading.set(false)
          this.loadAudit()
          this.loadDependencyAudit()
        },
        error: () => {
          if (stillCurrent()) {
            this.backToRepository()
          }
        },
      })
    } else {
      this.repositoriesService.dockerImageDetails(this.repositoryId, this.name).subscribe({
        next: (details) => {
          if (!stillCurrent()) {
            return
          }
          // Deleting the last tag leaves the image with none — nothing left to manage here.
          if (details.tags.length === 0) {
            this.backToRepository()
            return
          }
          this.dockerDetails.set(details)
          this.tagsPage.set(1)
          this.loading.set(false)
          this.loadImageScan()
        },
        error: () => {
          if (stillCurrent()) {
            this.backToRepository()
          }
        },
      })
    }
  }

  rescan(): void {
    this.loadAudit()
  }

  private loadAudit(): void {
    this.auditLoading.set(true)
    this.auditFailed.set(false)
    this.repositoriesService.npmPackageAudit(this.repositoryId, this.name).subscribe({
      next: (advisories) => {
        this.auditAdvisories.set(advisories)
        this.auditLoading.set(false)
      },
      error: () => {
        this.auditFailed.set(true)
        this.auditLoading.set(false)
      },
    })
  }

  readonly latestVersion = computed(() => {
    const details = this.npmDetails()
    if (!details) {
      return null
    }
    const latestTag = details.dist_tags.find((tag) => tag.tag === 'latest')
    if (latestTag) {
      return latestTag.version
    }
    return details.versions.length > 0
      ? details.versions[details.versions.length - 1].version
      : null
  })

  private loadDependencyAudit(): void {
    const version = this.latestVersion()
    if (!version) {
      this.depAuditLoading.set(false)
      return
    }
    this.depAuditLoading.set(true)
    this.depAuditFailed.set(false)
    this.repositoriesService.getDependencyAudit(this.repositoryId, this.name, version).subscribe({
      next: (result) => {
        this.depAuditResult.set(result)
        this.depAuditPage.set(1)
        this.depAuditLoading.set(false)
      },
      error: () => {
        this.depAuditFailed.set(true)
        this.depAuditLoading.set(false)
      },
    })
  }

  runDependencyScan(): void {
    const version = this.latestVersion()
    if (!version) {
      return
    }
    this.depAuditScanning.set(true)
    this.depAuditFailed.set(false)
    this.repositoriesService.scanDependencyTree(this.repositoryId, this.name, version).subscribe({
      next: (result) => {
        this.depAuditResult.set(result)
        this.depAuditPage.set(1)
        this.depAuditScanning.set(false)
      },
      error: () => {
        this.depAuditFailed.set(true)
        this.depAuditScanning.set(false)
      },
    })
  }

  onDepAuditSeverityFilterChange(value: string[]): void {
    this.depAuditSeverityFilter.set(value)
    this.depAuditPage.set(1)
  }

  goToDepAuditPage(page: number): void {
    this.depAuditPage.set(page)
  }

  readonly scannedTag = computed(() => {
    const details = this.dockerDetails()
    if (!details || details.tags.length === 0) {
      return null
    }
    return details.tags.find((tag) => tag.tag === 'latest')?.tag ?? details.tags[0].tag
  })

  private loadImageScan(): void {
    const tag = this.scannedTag()
    if (!tag) {
      this.imageScanLoading.set(false)
      return
    }
    this.imageScanLoading.set(true)
    this.imageScanFailed.set(false)
    this.repositoriesService.getDockerImageScan(this.repositoryId, this.name, tag).subscribe({
      next: (result) => {
        this.imageScanResult.set(result)
        this.imageScanPage.set(1)
        this.imageScanLoading.set(false)
      },
      error: () => {
        this.imageScanFailed.set(true)
        this.imageScanLoading.set(false)
      },
    })
  }

  runImageScan(): void {
    const tag = this.scannedTag()
    if (!tag) {
      return
    }
    this.imageScanScanning.set(true)
    this.imageScanFailed.set(false)
    this.repositoriesService.scanDockerImage(this.repositoryId, this.name, tag).subscribe({
      next: (result) => {
        this.imageScanResult.set(result)
        this.imageScanPage.set(1)
        this.imageScanScanning.set(false)
      },
      error: () => {
        this.imageScanFailed.set(true)
        this.imageScanScanning.set(false)
      },
    })
  }

  onImageScanSeverityFilterChange(value: string[]): void {
    this.imageScanSeverityFilter.set(value)
    this.imageScanPage.set(1)
  }

  goToImageScanPage(page: number): void {
    this.imageScanPage.set(page)
  }

  goToVersionsPage(page: number): void {
    this.versionsPage.set(page)
  }

  goToTagsPage(page: number): void {
    this.tagsPage.set(page)
  }

  backToRepository(): void {
    this.router.navigate(['/repositories', this.repositoryId])
  }

  deleteVersion(version: string): void {
    if (!confirm(`Supprimer la version ${version} de ${this.name} ?`)) {
      return
    }
    this.repositoriesService
      .deleteNpmPackageVersion(this.repositoryId, this.name, version)
      .subscribe({
        next: () => {
          this.reload()
          this.toastService.success(`Version ${version} supprimée.`)
        },
        error: () => this.toastService.error(`Échec de la suppression de la version ${version}.`),
      })
  }

  deleteWholePackage(): void {
    if (
      !confirm(`Supprimer entièrement le package ${this.name} ? Cette action est irréversible.`)
    ) {
      return
    }
    this.repositoriesService.deleteNpmPackage(this.repositoryId, this.name).subscribe({
      next: () => {
        this.backToRepository()
        this.toastService.success(`Package ${this.name} supprimé.`)
      },
      error: () => this.toastService.error('Échec de la suppression du package.'),
    })
  }

  deleteTag(tag: string): void {
    if (
      !confirm(
        `Supprimer le tag ${tag} de ${this.name} ? Toute autre étiquette pointant vers la même image sera aussi supprimée.`,
      )
    ) {
      return
    }
    this.repositoriesService.deleteDockerTag(this.repositoryId, this.name, tag).subscribe({
      next: () => {
        this.reload()
        this.toastService.success(`Tag ${tag} supprimé.`)
      },
      error: () => this.toastService.error(`Échec de la suppression du tag ${tag}.`),
    })
  }

  deleteWholeImage(): void {
    if (!confirm(`Supprimer entièrement l'image ${this.name} ? Cette action est irréversible.`)) {
      return
    }
    this.repositoriesService.deleteDockerImage(this.repositoryId, this.name).subscribe({
      next: () => {
        this.backToRepository()
        this.toastService.success(`Image ${this.name} supprimée.`)
      },
      error: () => this.toastService.error("Échec de la suppression de l'image."),
    })
  }
}
