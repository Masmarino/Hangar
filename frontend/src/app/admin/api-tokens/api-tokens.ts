import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
} from '@angular/core'
import { DatePipe } from '@angular/common'
import { Button, Card, Tooltip } from '@masmarino/gabarit'
import { AdminApiTokensService } from '../application/admin-api-tokens.service'
import { AdminApiToken } from '../domain/admin-api-token.entity'
import { ToastService } from '../../shared/toast.service'

@Component({
  selector: 'app-api-tokens-admin',
  standalone: true,
  imports: [Button, Card, DatePipe, Tooltip],
  templateUrl: './api-tokens.html',
  styleUrl: './api-tokens.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ApiTokensAdmin {
  private readonly tokensService = inject(AdminApiTokensService)
  private readonly toastService = inject(ToastService)

  /** Set only when embedded in an organization's own admin page — scopes the list to it. */
  readonly organizationId = input<string | undefined>(undefined)

  private readonly tokens = signal<AdminApiToken[]>([])

  readonly activeTokens = computed(() => this.tokens().filter((t) => !t.revoked_at))
  readonly revokedTokens = computed(() => this.tokens().filter((t) => t.revoked_at))

  // effect(), not ngOnInit — this component is reused across organizations on the same route.
  constructor() {
    effect(() => {
      this.organizationId()
      this.reload()
    })
  }

  private reload(): void {
    this.tokensService.list(this.organizationId()).subscribe((tokens) => this.tokens.set(tokens))
  }

  revoke(token: AdminApiToken): void {
    if (!confirm(`Révoquer le jeton « ${token.label} » de ${token.username} ?`)) {
      return
    }
    this.tokensService.revoke(token.id).subscribe({
      next: () => {
        this.reload()
        this.toastService.success(`Jeton « ${token.label} » révoqué.`)
      },
      error: () => this.toastService.error(`Échec de la révocation du jeton « ${token.label} ».`),
    })
  }
}
