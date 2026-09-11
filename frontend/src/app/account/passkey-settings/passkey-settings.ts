import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { firstValueFrom } from 'rxjs'
import { Button, Card, GbtInput } from '@masmarino/gabarit'
import { MfaService } from '../application/mfa.service'
import { PasskeySummary } from '../domain/mfa.types'
import { createPasskeyCredential, passkeysSupported } from '../../shared/webauthn-browser'
import { ToastService } from '../../shared/toast.service'

@Component({
  selector: 'app-passkey-settings',
  standalone: true,
  imports: [Button, Card, GbtInput, FormsModule],
  templateUrl: './passkey-settings.html',
  styleUrl: './passkey-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PasskeySettings implements OnInit {
  private readonly mfaService = inject(MfaService)
  private readonly toastService = inject(ToastService)

  readonly supported = passkeysSupported()
  readonly loading = signal(true)
  readonly passkeys = signal<PasskeySummary[]>([])
  readonly errorMessage = signal<string | null>(null)

  readonly addingName = signal(false)
  readonly newPasskeyName = signal('')
  readonly registering = signal(false)

  readonly deletePasswords = signal<Record<string, string>>({})
  readonly deletingIds = signal<ReadonlySet<string>>(new Set())

  ngOnInit(): void {
    this.reload()
  }

  private reload(): void {
    this.mfaService.listPasskeys().subscribe({
      next: (passkeys) => {
        this.passkeys.set(passkeys)
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.errorMessage.set("Échec du chargement des clés d'accès.")
      },
    })
  }

  startAdding(): void {
    this.newPasskeyName.set('')
    this.addingName.set(true)
  }

  cancelAdding(): void {
    this.addingName.set(false)
  }

  async register(): Promise<void> {
    if (this.newPasskeyName().trim() === '' || this.registering()) {
      return
    }
    this.registering.set(true)
    try {
      const start = await firstValueFrom(this.mfaService.startPasskeyRegistration())
      const credential = await createPasskeyCredential(start.public_key)
      await firstValueFrom(
        this.mfaService.finishPasskeyRegistration(
          start.challenge_id,
          credential,
          this.newPasskeyName(),
        ),
      )
      this.addingName.set(false)
      this.reload()
      this.toastService.success('Clé d’accès enregistrée.')
    } catch (err) {
      console.error('Passkey registration failed:', err)
      this.toastService.error("Échec de l'enregistrement de la clé d'accès. Réessayez.")
    } finally {
      this.registering.set(false)
    }
  }

  passwordFor(id: string): string {
    return this.deletePasswords()[id] ?? ''
  }

  setPasswordFor(id: string, value: string): void {
    this.deletePasswords.update((passwords) => ({ ...passwords, [id]: value }))
  }

  delete(id: string): void {
    const password = this.passwordFor(id)
    if (password.trim() === '' || this.deletingIds().has(id)) {
      return
    }
    this.deletingIds.update((ids) => new Set(ids).add(id))
    this.mfaService.deletePasskey(id, password).subscribe({
      next: () => {
        this.stopDeleting(id)
        this.setPasswordFor(id, '')
        this.reload()
        this.toastService.success('Clé d’accès supprimée.')
      },
      error: () => {
        this.stopDeleting(id)
        this.toastService.error('Mot de passe incorrect.')
      },
    })
  }

  private stopDeleting(id: string): void {
    this.deletingIds.update((ids) => {
      const next = new Set(ids)
      next.delete(id)
      return next
    })
  }
}
