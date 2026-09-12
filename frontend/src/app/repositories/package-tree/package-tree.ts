import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
} from '@angular/core'
import { RouterLink } from '@angular/router'
import { Icon } from '@masmarino/gabarit'
import { RepositoriesService } from '../application/repositories.service'
import { RepositoryPackages } from '../domain/repository.entity'
import { VulnerabilitySummaryBadge } from '../vulnerability-summary/vulnerability-summary'

@Component({
  selector: 'app-package-tree',
  standalone: true,
  imports: [Icon, RouterLink, VulnerabilitySummaryBadge],
  templateUrl: './package-tree.html',
  styleUrl: './package-tree.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PackageTree {
  private readonly repositoriesService = inject(RepositoriesService)

  readonly repositoryId = input.required<string>()

  readonly tree = signal<RepositoryPackages | null>(null)
  readonly loading = signal(true)
  readonly error = signal<string | null>(null)

  constructor() {
    effect(() => {
      this.repositoryId()
      this.reload()
    })
  }

  private reload(): void {
    this.loading.set(true)
    this.error.set(null)
    const requestedId = this.repositoryId()
    this.repositoriesService.packages(requestedId).subscribe({
      next: (tree) => {
        if (requestedId !== this.repositoryId()) {
          return
        }
        this.tree.set(tree)
        this.loading.set(false)
      },
      error: () => {
        if (requestedId !== this.repositoryId()) {
          return
        }
        this.loading.set(false)
        this.error.set('Échec du chargement des packages.')
      },
    })
  }

  readonly npmRows = computed(() => {
    const t = this.tree()
    if (!t || t.format !== 'npm') {
      return []
    }
    const repositoryId = this.repositoryId()
    return t.packages.map((pkg) => ({
      pkg,
      link: ['/repositories', repositoryId, 'packages', 'npm', pkg.name],
    }))
  })

  readonly dockerRows = computed(() => {
    const t = this.tree()
    if (!t || t.format !== 'docker') {
      return []
    }
    const repositoryId = this.repositoryId()
    return t.images.map((image) => ({
      image,
      link: ['/repositories', repositoryId, 'packages', 'docker', image.image_name],
    }))
  })
}
