import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { HttpErrorResponse } from '@angular/common/http'
import * as QRCode from 'qrcode'
import { Button, Card, GbtInput, Tooltip } from '@masmarino/gabarit'
import { MfaService } from '../application/mfa.service'
import { MfaStatus } from '../domain/mfa.types'
import { ToastService } from '../../shared/toast.service'

type ViewState = 'loading' | 'disabled' | 'enrolling' | 'backup-codes' | 'enabled'

@Component({
  selector: 'app-mfa-settings',
  standalone: true,
  imports: [Button, Card, GbtInput, FormsModule, Tooltip],
  templateUrl: './mfa-settings.html',
  styleUrl: './mfa-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MfaSettings implements OnInit {
  private readonly mfaService = inject(MfaService)
  private readonly toastService = inject(ToastService)

  readonly state = signal<ViewState>('loading')
  readonly status = signal<MfaStatus | null>(null)
  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  readonly enrollmentSecret = signal('')
  readonly qrCodeDataUrl = signal<string | null>(null)
  readonly confirmCode = signal('')

  readonly backupCodes = signal<string[]>([])

  readonly disablePassword = signal('')
  readonly regeneratePassword = signal('')
  readonly regeneratedCodes = signal<string[] | null>(null)

  ngOnInit(): void {
    this.reload()
  }

  private reload(): void {
    this.mfaService.getStatus().subscribe((status) => {
      this.status.set(status)
      this.state.set(status.totp_enabled ? 'enabled' : 'disabled')
    })
  }

  startEnrollment(): void {
    this.errorMessage.set(null)
    this.mfaService.enrollTotp().subscribe((enrollment) => {
      this.enrollmentSecret.set(enrollment.secret)
      QRCode.toDataURL(enrollment.otpauth_url)
        .then((dataUrl) => this.qrCodeDataUrl.set(dataUrl))
        .catch(() => this.qrCodeDataUrl.set(null))
      this.state.set('enrolling')
    })
  }

  cancelEnrollment(): void {
    this.confirmCode.set('')
    this.qrCodeDataUrl.set(null)
    this.state.set('disabled')
  }

  confirmEnrollment(): void {
    if (this.confirmCode().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.mfaService.confirmTotp(this.confirmCode()).subscribe({
      next: (result) => {
        this.submitting.set(false)
        this.backupCodes.set(result.backup_codes)
        this.confirmCode.set('')
        this.state.set('backup-codes')
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Code invalide.')
      },
    })
  }

  acknowledgeBackupCodes(): void {
    this.backupCodes.set([])
    this.reload()
  }

  disable(): void {
    if (this.disablePassword().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.mfaService.disableTotp(this.disablePassword()).subscribe({
      next: () => {
        this.submitting.set(false)
        this.disablePassword.set('')
        this.reload()
        this.toastService.success('Double authentification désactivée.')
      },
      error: (err: HttpErrorResponse) => {
        this.submitting.set(false)
        this.toastService.error(
          err.status === 400 ? 'Mot de passe incorrect.' : 'Échec de la désactivation.',
        )
      },
    })
  }

  regenerateBackupCodes(): void {
    if (this.regeneratePassword().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.mfaService.regenerateBackupCodes(this.regeneratePassword()).subscribe({
      next: (result) => {
        this.submitting.set(false)
        this.regeneratePassword.set('')
        this.regeneratedCodes.set(result.backup_codes)
        this.toastService.success('Nouveaux codes de secours générés.')
      },
      error: (err: HttpErrorResponse) => {
        this.submitting.set(false)
        this.toastService.error(
          err.status === 400 ? 'Mot de passe incorrect.' : 'Échec de la régénération.',
        )
      },
    })
  }

  dismissRegeneratedCodes(): void {
    this.regeneratedCodes.set(null)
    this.reload()
  }
}
