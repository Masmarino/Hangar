import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { Router } from '@angular/router'
import { Button, Table, TableColumn } from '@masmarino/gabarit'
import { CreateRepositoryModal } from '../create-repository-modal/create-repository-modal'
import { RepositoriesService } from '../application/repositories.service'
import { RepositorySummary } from '../domain/repository.entity'

@Component({
  selector: 'app-repositories-list',
  standalone: true,
  imports: [Table, Button, CreateRepositoryModal],
  templateUrl: './repositories-list.html',
  styleUrl: './repositories-list.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RepositoriesList implements OnInit {
  private readonly repositoriesService = inject(RepositoriesService)
  private readonly router = inject(Router)

  readonly repositories = signal<RepositorySummary[]>([])
  readonly showCreateModal = signal(false)
  readonly loading = signal(true)
  readonly error = signal<string | null>(null)

  readonly columns: TableColumn<RepositorySummary>[] = [
    { key: 'name', label: 'Nom' },
    { key: 'format', label: 'Format' },
    { key: 'repo_type', label: 'Type' },
  ]
  readonly rowId = (r: RepositorySummary): string => r.id

  ngOnInit(): void {
    this.reload()
  }

  reload(): void {
    this.error.set(null)
    this.repositoriesService.list().subscribe({
      next: (repositories) => {
        this.repositories.set(repositories)
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.error.set('Échec du chargement des dépôts.')
      },
    })
  }

  onCreated(): void {
    this.showCreateModal.set(false)
    this.reload()
  }

  openDetail(repository: RepositorySummary): void {
    this.router.navigate(['/repositories', repository.id])
  }
}
