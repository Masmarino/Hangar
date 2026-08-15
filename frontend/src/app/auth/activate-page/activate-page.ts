import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { ActivatedRoute, Router } from '@angular/router'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'

@Component({
  selector: 'app-activate-page',
  standalone: true,
  imports: [ReactiveFormsModule, GbtInput, Button],
  templateUrl: './activate-page.html',
  styleUrl: '../login-page/login-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ActivatePage {
  private readonly auth = inject(AuthService)
  private readonly route = inject(ActivatedRoute)
  private readonly router = inject(Router)

  private readonly token = this.route.snapshot.queryParamMap.get('token') ?? ''
  readonly tokenMissing = this.token === ''

  readonly form = new FormGroup({
    newPassword: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(8)],
    }),
    confirmPassword: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  get passwordMismatch(): boolean {
    const { newPassword, confirmPassword } = this.form.getRawValue()
    return confirmPassword !== '' && newPassword !== confirmPassword
  }

  submit(): void {
    if (this.form.invalid || this.passwordMismatch || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { newPassword } = this.form.getRawValue()
    this.auth.activate(this.token, newPassword).subscribe({
      next: () => this.router.navigateByUrl('/login'),
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set(
          "Ce lien d'activation est invalide ou a expiré. Demandez à un administrateur de vous renvoyer une invitation.",
        )
      },
    })
  }
}
