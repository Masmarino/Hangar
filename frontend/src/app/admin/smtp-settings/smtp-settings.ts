import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { Button, Card, GbtInput, Select, SelectOption } from '@masmarino/gabarit'
import { SmtpSettingsService } from '../application/smtp-settings.service'
import { SmtpSecurity } from '../domain/smtp-settings.entity'

const SECURITY_OPTIONS: SelectOption<SmtpSecurity>[] = [
  { value: 'start_tls', label: 'STARTTLS (port 587 usuellement)' },
  { value: 'tls', label: 'TLS implicite (port 465 usuellement)' },
  { value: 'none', label: 'Aucun (réseau interne de confiance uniquement)' },
]

@Component({
  selector: 'app-smtp-settings',
  standalone: true,
  imports: [Button, Card, GbtInput, Select, FormsModule],
  templateUrl: './smtp-settings.html',
  styleUrl: './smtp-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SmtpSettingsAdmin implements OnInit {
  private readonly settingsService = inject(SmtpSettingsService)

  readonly securityOptions = SECURITY_OPTIONS

  readonly host = signal('')
  readonly port = signal('587')
  readonly username = signal('')
  readonly password = signal('')
  readonly fromName = signal('Hangar')
  readonly fromAddress = signal('')
  readonly security = signal<SmtpSecurity>('start_tls')
  readonly passwordSet = signal(false)

  readonly loading = signal(true)
  readonly saving = signal(false)
  readonly saved = signal(false)
  readonly errorMessage = signal<string | null>(null)

  readonly testRecipient = signal('')
  readonly sendingTest = signal(false)
  readonly testSent = signal(false)
  readonly testErrorMessage = signal<string | null>(null)

  ngOnInit(): void {
    this.settingsService.get().subscribe((settings) => {
      if (settings) {
        this.host.set(settings.host)
        this.port.set(String(settings.port))
        this.username.set(settings.username)
        this.fromName.set(settings.from_name)
        this.fromAddress.set(settings.from_address)
        this.security.set(settings.security)
        this.passwordSet.set(settings.password_set)
      }
      this.loading.set(false)
    })
  }

  // Errors stay hidden until a save is attempted — a freshly opened form isn't a mistake yet.
  readonly attemptedSave = signal(false)

  private readonly rawPortError = computed(() => {
    const parsed = Number(this.port())
    if (this.port().trim() === '' || !Number.isInteger(parsed)) {
      return 'Doit être un nombre entier.'
    }
    if (parsed < 1 || parsed > 65_535) {
      return 'Doit être entre 1 et 65535.'
    }
    return null
  })

  private readonly rawHostError = computed(() =>
    this.host().trim() === '' ? "L'hôte est requis." : null,
  )

  private readonly rawUsernameError = computed(() =>
    this.username().trim() === '' ? "L'identifiant est requis." : null,
  )

  private readonly rawFromAddressError = computed(() =>
    this.fromAddress().includes('@') ? null : 'Doit être une adresse e-mail valide.',
  )

  private readonly rawFromNameError = computed(() =>
    this.fromName().trim() === '' ? "Le nom d'expéditeur est requis." : null,
  )

  private readonly rawPasswordError = computed(() => {
    if (!this.passwordSet() && this.password().trim() === '') {
      return 'Le mot de passe est requis lors de la première configuration.'
    }
    return null
  })

  readonly hostError = computed(() => (this.attemptedSave() ? this.rawHostError() : null))
  readonly portError = computed(() => (this.attemptedSave() ? this.rawPortError() : null))
  readonly usernameError = computed(() => (this.attemptedSave() ? this.rawUsernameError() : null))
  readonly fromAddressError = computed(() =>
    this.attemptedSave() ? this.rawFromAddressError() : null,
  )
  readonly fromNameError = computed(() => (this.attemptedSave() ? this.rawFromNameError() : null))
  readonly passwordError = computed(() => (this.attemptedSave() ? this.rawPasswordError() : null))

  readonly hasErrors = computed(
    () =>
      this.attemptedSave() &&
      (this.rawHostError() !== null ||
        this.rawPortError() !== null ||
        this.rawUsernameError() !== null ||
        this.rawFromNameError() !== null ||
        this.rawFromAddressError() !== null ||
        this.rawPasswordError() !== null),
  )

  save(): void {
    this.saved.set(false)
    this.errorMessage.set(null)
    this.attemptedSave.set(true)
    if (this.hasErrors()) {
      return
    }
    this.saving.set(true)
    this.settingsService
      .update({
        host: this.host(),
        port: Number(this.port()),
        username: this.username(),
        password: this.password().trim() === '' ? undefined : this.password(),
        from_name: this.fromName(),
        from_address: this.fromAddress(),
        security: this.security(),
      })
      .subscribe({
        next: () => {
          this.saving.set(false)
          this.saved.set(true)
          this.passwordSet.set(true)
          this.password.set('')
        },
        error: () => {
          this.saving.set(false)
          this.errorMessage.set('Échec de la mise à jour des paramètres SMTP.')
        },
      })
  }

  sendTest(): void {
    this.testSent.set(false)
    this.testErrorMessage.set(null)
    if (this.testRecipient().trim() === '') {
      return
    }
    this.sendingTest.set(true)
    this.settingsService.sendTestEmail(this.testRecipient()).subscribe({
      next: () => {
        this.sendingTest.set(false)
        this.testSent.set(true)
      },
      error: () => {
        this.sendingTest.set(false)
        this.testErrorMessage.set(
          "Échec de l'envoi de l'e-mail de test. Vérifiez la configuration.",
        )
      },
    })
  }
}
