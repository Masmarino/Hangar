import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import {
  AbstractControl,
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms'
import { Button, Card, GbtInput, Tab, Tabs } from '@masmarino/gabarit'
import { ApiTokensList } from '../../tokens/api-tokens-list/api-tokens-list'
import { MeService } from '../../shell/application/me.service'
import { DatePipe } from '@angular/common'
import { MfaSettings } from '../mfa-settings/mfa-settings'
import { PasskeySettings } from '../passkey-settings/passkey-settings'

function passwordsMatch(group: AbstractControl): ValidationErrors | null {
  const newPassword = group.get('newPassword')?.value
  const confirmPassword = group.get('confirmPassword')?.value
  return newPassword === confirmPassword ? null : { passwordsMismatch: true }
}

@Component({
  selector: 'app-account-page',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    Button,
    GbtInput,
    ApiTokensList,
    Card,
    DatePipe,
    MfaSettings,
    PasskeySettings,
    Tabs,
    Tab,
  ],
  templateUrl: './account-page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AccountPage {
  readonly me = inject(MeService)

  readonly form = new FormGroup(
    {
      currentPassword: new FormControl('', {
        nonNullable: true,
        validators: [Validators.required],
      }),
      newPassword: new FormControl('', {
        nonNullable: true,
        validators: [Validators.required, Validators.minLength(8)],
      }),
      confirmPassword: new FormControl('', {
        nonNullable: true,
        validators: [Validators.required],
      }),
    },
    { validators: passwordsMatch },
  )

  readonly errorMessage = signal<string | null>(null)
  readonly successMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  get confirmPasswordError(): string | null {
    const control = this.form.controls.confirmPassword
    return this.form.hasError('passwordsMismatch') && control.touched
      ? 'Les mots de passe ne correspondent pas.'
      : null
  }

  get newPasswordError(): string | null {
    const control = this.form.controls.newPassword
    return control.hasError('minlength') && control.touched
      ? 'Le mot de passe doit contenir au moins 8 caractères.'
      : null
  }

  submit(): void {
    if (this.form.invalid || this.submitting()) return
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.successMessage.set(null)
    const { currentPassword, newPassword } = this.form.getRawValue()
    this.me.changePassword(currentPassword, newPassword).subscribe({
      next: () => {
        this.submitting.set(false)
        this.successMessage.set('Mot de passe changé avec succès.')
        this.form.reset({ currentPassword: '', newPassword: '', confirmPassword: '' })
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Mot de passe actuel incorrect ou nouveau mot de passe invalide.')
        this.form.patchValue({ currentPassword: '' })
      },
    })
  }
}
