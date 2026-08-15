import { ChangeDetectionStrategy, Component, inject, output, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { Button, GbtInput, Modal } from '@masmarino/gabarit'
import { OrganizationsService } from '../application/organizations.service'

@Component({
  selector: 'app-create-organization-modal',
  standalone: true,
  imports: [ReactiveFormsModule, Modal, GbtInput, Button],
  templateUrl: './create-organization-modal.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CreateOrganizationModal {
  private readonly organizationsService = inject(OrganizationsService)

  readonly created = output<void>()
  readonly cancelled = output<void>()

  readonly form = new FormGroup({
    slug: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    displayName: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })

  readonly creating = signal(false)

  submit(): void {
    if (this.form.invalid || this.creating()) {
      return
    }
    this.creating.set(true)
    const { slug, displayName } = this.form.getRawValue()
    this.organizationsService.create(slug, displayName).subscribe({
      next: () => {
        this.creating.set(false)
        this.created.emit()
      },
      error: () => this.creating.set(false),
    })
  }
}
