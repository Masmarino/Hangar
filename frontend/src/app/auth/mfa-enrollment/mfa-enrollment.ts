import {
  ChangeDetectionStrategy,
  Component,
  EventEmitter,
  Output,
  inject,
  input,
  signal,
} from '@angular/core'
import { FormsModule } from '@angular/forms'
import { firstValueFrom } from 'rxjs'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import { createPasskeyCredential, passkeysSupported } from '../../shared/webauthn-browser'

type SetupStep = 'choice' | 'totp-enroll' | 'backup-codes' | 'passkey'

/** Mandatory first-time MFA enrollment — every account needs a factor before it can be used. */
@Component({
  selector: 'app-mfa-enrollment',
  standalone: true,
  imports: [FormsModule, GbtInput, Button],
  templateUrl: './mfa-enrollment.html',
  styleUrl: './mfa-enrollment.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MfaEnrollmentPage {
  private readonly auth = inject(AuthService)

  readonly mfaToken = input.required<string>()

  @Output() readonly completed = new EventEmitter<void>()

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)
  readonly passkeysSupported = passkeysSupported()

  readonly setupStep = signal<SetupStep>('choice')
  readonly totpSecret = signal('')
  readonly qrCodeDataUrl = signal<string | null>(null)
  readonly setupCode = signal('')
  readonly passkeyName = signal('')
  readonly backupCodes = signal<string[]>([])

  chooseTotpSetup(): void {
    if (this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.auth.startTotpSetup(this.mfaToken()).subscribe({
      next: (enrollment) => {
        this.submitting.set(false)
        this.totpSecret.set(enrollment.secret)
        // Only needed for this one-time enrollment screen — not worth shipping to every login-page visit.
        import('qrcode')
          .then((QRCode) => QRCode.toDataURL(enrollment.otpauth_url))
          .then((dataUrl) => this.qrCodeDataUrl.set(dataUrl))
          .catch(() => this.qrCodeDataUrl.set(null))
        this.setupStep.set('totp-enroll')
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set("Échec de la préparation de l'application d'authentification.")
      },
    })
  }

  choosePasskeySetup(): void {
    this.errorMessage.set(null)
    this.setupStep.set('passkey')
  }

  backToChoice(): void {
    this.errorMessage.set(null)
    this.setupCode.set('')
    this.passkeyName.set('')
    this.setupStep.set('choice')
  }

  confirmTotpSetup(): void {
    if (this.setupCode().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.auth.confirmTotpSetup(this.mfaToken(), this.setupCode()).subscribe({
      next: (result) => {
        this.submitting.set(false)
        this.backupCodes.set(result.backup_codes)
        this.setupStep.set('backup-codes')
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Code invalide.')
      },
    })
  }

  finishSetup(): void {
    this.completed.emit()
  }

  async registerSetupPasskey(): Promise<void> {
    if (this.passkeyName().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    try {
      const start = await firstValueFrom(this.auth.startPasskeySetup(this.mfaToken()))
      const credential = await createPasskeyCredential(start.public_key)
      await firstValueFrom(
        this.auth.finishPasskeySetup(
          this.mfaToken(),
          start.challenge_id,
          credential,
          this.passkeyName(),
        ),
      )
      this.completed.emit()
    } catch (err) {
      console.error('Passkey registration failed:', err)
      this.submitting.set(false)
      this.errorMessage.set("Échec de l'enregistrement de la clé d'accès. Réessayez.")
    }
  }
}
