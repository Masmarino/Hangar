import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import {
  FormControl,
  FormGroup,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms'
import { Router, RouterLink } from '@angular/router'
import { firstValueFrom } from 'rxjs'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import { getPasskeyAssertion, passkeysSupported } from '../../shared/webauthn-browser'
import { MfaEnrollmentPage } from '../mfa-enrollment/mfa-enrollment'

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [ReactiveFormsModule, FormsModule, GbtInput, Button, MfaEnrollmentPage, RouterLink],
  templateUrl: './login-page.html',
  styleUrl: './login-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginPage implements OnInit {
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)

  readonly form = new FormGroup({
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)
  readonly ssoType = signal<'ldap' | 'oidc' | null>(null)
  // Defaults to visible on a failed/pending check — never hide a legitimate way to sign up
  // just because this one best-effort request didn't come back in time.
  readonly registrationEnabled = signal(true)

  ngOnInit(): void {
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = hashParams.get('token')
    if (token) {
      this.auth.completeExternalLogin(token)
      // Clear the fragment so the token never lingers in browser history/bookmarks.
      history.replaceState(null, '', window.location.pathname + window.location.search)
      this.router.navigateByUrl('/')
      return
    }

    this.auth.getSsoConfig().subscribe({
      next: (config) => {
        this.ssoType.set(config.type)
        this.registrationEnabled.set(config.registration_enabled)
      },
      // Local login is always a safe fallback — never block the form on this check failing.
      error: () => this.ssoType.set(null),
    })
  }

  // null until a login response requires a second factor — the template swaps to the MFA
  // form the moment it's set.
  readonly mfaToken = signal<string | null>(null)
  readonly mfaSetupRequired = signal(false)
  // Which factor(s) the account actually has — the verify form only shows what applies,
  // instead of always defaulting to a TOTP/backup-code field even for a passkey-only account.
  readonly mfaHasTotp = signal(false)
  readonly mfaHasPasskey = signal(false)
  readonly useBackupCode = signal(false)
  readonly mfaForm = new FormGroup({
    code: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })
  readonly passkeysSupported = passkeysSupported()

  submit(): void {
    if (this.form.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { username, password } = this.form.getRawValue()
    const attempt =
      this.ssoType() === 'ldap'
        ? this.auth.loginWithLdap(username, password)
        : this.auth.login(username, password)
    attempt.subscribe({
      next: (outcome) => {
        if (outcome.mfaRequired && outcome.mfaToken) {
          this.submitting.set(false)
          this.mfaToken.set(outcome.mfaToken)
          this.mfaSetupRequired.set(!!outcome.mfaSetupRequired)
          this.mfaHasTotp.set(!!outcome.mfaHasTotp)
          this.mfaHasPasskey.set(!!outcome.mfaHasPasskey)
        } else {
          this.router.navigateByUrl('/')
        }
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Identifiants invalides')
      },
    })
  }

  toggleBackupCode(): void {
    this.useBackupCode.update((value) => !value)
    this.mfaForm.reset()
    this.errorMessage.set(null)
  }

  submitMfa(): void {
    const mfaToken = this.mfaToken()
    if (!mfaToken || this.mfaForm.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { code } = this.mfaForm.getRawValue()
    const verify = this.useBackupCode()
      ? this.auth.verifyMfa(mfaToken, undefined, code)
      : this.auth.verifyMfa(mfaToken, code, undefined)
    verify.subscribe({
      next: () => this.router.navigateByUrl('/'),
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set(this.useBackupCode() ? 'Code de secours invalide.' : 'Code invalide.')
      },
    })
  }

  async submitPasskey(): Promise<void> {
    const mfaToken = this.mfaToken()
    if (!mfaToken || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    try {
      const start = await firstValueFrom(this.auth.startMfaPasskey(mfaToken))
      const credential = await getPasskeyAssertion(start.public_key)
      await firstValueFrom(this.auth.finishMfaPasskey(mfaToken, start.challenge_id, credential))
      this.router.navigateByUrl('/')
    } catch {
      this.submitting.set(false)
      this.errorMessage.set("Échec de l'authentification par clé d'accès.")
    }
  }

  onEnrollmentCompleted(): void {
    this.router.navigateByUrl('/')
  }
}
