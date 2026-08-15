import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { Router, RouterLink } from '@angular/router'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import { MfaEnrollmentPage } from '../mfa-enrollment/mfa-enrollment'

@Component({
  selector: 'app-register-page',
  standalone: true,
  imports: [ReactiveFormsModule, GbtInput, Button, MfaEnrollmentPage, RouterLink],
  templateUrl: './register-page.html',
  styleUrl: '../login-page/login-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RegisterPage {
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)

  readonly form = new FormGroup({
    username: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.pattern(/^[A-Za-z][A-Za-z0-9_-]{2,31}$/)],
    }),
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(8)],
    }),
  })

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  // null until registration returns an mfa_token — the template then swaps to enrollment.
  readonly mfaToken = signal<string | null>(null)

  submit(): void {
    if (this.form.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { username, email, password } = this.form.getRawValue()
    this.auth.register(username, email, password).subscribe({
      next: (outcome) => {
        this.submitting.set(false)
        if (outcome.mfaToken) {
          this.mfaToken.set(outcome.mfaToken)
        }
      },
      error: (err: unknown) => {
        this.submitting.set(false)
        const backendMessage = (err as { error?: { error?: string } })?.error?.error ?? ''
        this.errorMessage.set(this.messageFor(backendMessage))
      },
    })
  }

  onEnrollmentCompleted(): void {
    this.router.navigateByUrl('/')
  }

  private messageFor(backendMessage: string): string {
    if (backendMessage.includes('username already taken')) {
      return 'Ce nom d’utilisateur est déjà pris.'
    }
    if (backendMessage.includes('invalid email')) {
      return 'Adresse e-mail invalide.'
    }
    if (backendMessage.includes('password must be at least')) {
      return 'Le mot de passe doit comporter au moins 8 caractères.'
    }
    if (backendMessage.includes('not available on this organization')) {
      return "L'inscription publique n'est pas disponible sur cette organisation."
    }
    if (backendMessage.includes('currently disabled')) {
      return "La création de compte est actuellement désactivée par l'administrateur."
    }
    if (backendMessage.includes('invalid username')) {
      return "Nom d'utilisateur invalide : 3 à 32 caractères, doit commencer par une lettre."
    }
    return 'Impossible de créer le compte. Réessayez.'
  }
}
