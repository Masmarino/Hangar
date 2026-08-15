import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core'
import { DatePipe } from '@angular/common'
import { Button, Card } from '@masmarino/gabarit'
import { AdminApiTokensService } from '../application/admin-api-tokens.service'
import { AdminApiToken } from '../domain/admin-api-token.entity'

@Component({
  selector: 'app-api-tokens-admin',
  standalone: true,
  imports: [Button, Card, DatePipe],
  templateUrl: './api-tokens.html',
  styleUrl: './api-tokens.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ApiTokensAdmin implements OnInit {
  private readonly tokensService = inject(AdminApiTokensService)

  private readonly tokens = signal<AdminApiToken[]>([])

  readonly activeTokens = computed(() => this.tokens().filter((t) => !t.revoked_at))
  readonly revokedTokens = computed(() => this.tokens().filter((t) => t.revoked_at))
  readonly revokeError = signal<string | null>(null)

  ngOnInit(): void {
    this.reload()
  }

  private reload(): void {
    this.tokensService.list().subscribe((tokens) => this.tokens.set(tokens))
  }

  revoke(token: AdminApiToken): void {
    if (!confirm(`Révoquer le jeton « ${token.label} » de ${token.username} ?`)) {
      return
    }
    this.revokeError.set(null)
    this.tokensService.revoke(token.id).subscribe({
      next: () => this.reload(),
      error: () => this.revokeError.set(`Échec de la révocation du jeton « ${token.label} ».`),
    })
  }
}
