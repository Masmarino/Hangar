import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { FormControl, ReactiveFormsModule } from '@angular/forms'
import { DatePipe } from '@angular/common'
import { Button, GbtInput, Modal, Table, TableColumn } from '@masmarino/gabarit'
import { ApiToken } from '../domain/api-token.entity'
import { ApiTokensApplicationService } from '../application/api-tokens.application-service'

@Component({
  selector: 'app-api-tokens-list',
  standalone: true,
  imports: [ReactiveFormsModule, Table, Button, GbtInput, Modal],
  providers: [DatePipe],
  templateUrl: './api-tokens-list.html',
  styleUrl: './api-tokens-list.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ApiTokensList implements OnInit {
  private readonly tokenService = inject(ApiTokensApplicationService)
  private readonly datePipe = inject(DatePipe)

  readonly tokens = signal<ApiToken[]>([])
  readonly showCreateForm = signal(false)
  readonly createdToken = signal<string | null>(null)
  readonly newLabel = new FormControl('', { nonNullable: true })

  readonly columns: TableColumn<ApiToken>[] = [
    { key: 'label', label: 'Nom' },
    {
      key: 'created_at',
      label: 'Créé le',
      format: (t) => this.datePipe.transform(t.created_at, 'short') ?? '',
    },
  ]
  readonly rowId = (t: ApiToken): string => t.id

  ngOnInit(): void {
    this.reload()
  }

  reload(): void {
    this.tokenService.list().subscribe((tokens) => this.tokens.set(tokens))
  }

  readonly creatingToken = signal(false)

  createToken(): void {
    const label = this.newLabel.value.trim()
    if (!label || this.creatingToken()) return
    this.creatingToken.set(true)
    this.tokenService.create(label).subscribe({
      next: (result) => {
        this.creatingToken.set(false)
        this.createdToken.set(result.token)
        this.newLabel.setValue('')
        this.showCreateForm.set(false)
        this.reload()
      },
      error: () => this.creatingToken.set(false),
    })
  }

  readonly revokeError = signal<string | null>(null)

  revokeToken(token: ApiToken): void {
    if (
      !confirm(
        `Révoquer le token "${token.label}" ? Toute intégration npm qui l'utilise cessera de fonctionner.`,
      )
    )
      return
    this.revokeError.set(null)
    this.tokenService.revoke(token.id).subscribe({
      next: () => this.reload(),
      error: () => this.revokeError.set(`Échec de la révocation du token "${token.label}".`),
    })
  }

  dismissCreatedToken(): void {
    this.createdToken.set(null)
  }
}
