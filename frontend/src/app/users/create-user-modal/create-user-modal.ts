import { ChangeDetectionStrategy, Component, inject, output, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { Button, Checkbox, GbtInput, Modal } from '@masmarino/gabarit'
import { UsersService } from '../application/users.service'

@Component({
  selector: 'app-create-user-modal',
  standalone: true,
  imports: [ReactiveFormsModule, Modal, GbtInput, Checkbox, Button],
  templateUrl: './create-user-modal.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CreateUserModal {
  private readonly usersService = inject(UsersService)

  readonly created = output<void>()
  readonly cancelled = output<void>()

  readonly form = new FormGroup({
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    isSuperAdmin: new FormControl(false, { nonNullable: true }),
  })

  readonly creating = signal(false)

  submit(): void {
    if (this.form.invalid || this.creating()) {
      return
    }
    this.creating.set(true)
    const { username, email, isSuperAdmin } = this.form.getRawValue()
    this.usersService.create(username, email, isSuperAdmin).subscribe({
      next: () => {
        this.creating.set(false)
        this.created.emit()
      },
      error: () => this.creating.set(false),
    })
  }
}
