import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  input,
  output,
  signal,
} from '@angular/core'
import { FormsModule } from '@angular/forms'
import { Button, Modal, Select } from '@masmarino/gabarit'
import { ROLE_OPTIONS, Role } from '../domain/permission.entity'

@Component({
  selector: 'app-permission-role-editor',
  standalone: true,
  imports: [Modal, Button, Select, FormsModule],
  templateUrl: './permission-role-editor.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PermissionRoleEditor {
  readonly isOpen = input.required<boolean>()
  readonly label = input.required<string>()
  readonly currentRole = input.required<Role>()
  readonly subjectKind = input<'user' | 'repository'>('user')
  readonly saving = input(false)

  readonly roleChanged = output<Role>()
  readonly revoked = output<void>()
  readonly closed = output<void>()

  readonly selectedRole = signal<Role>('read')
  readonly roleOptions = ROLE_OPTIONS

  readonly modalTitle = computed(() =>
    this.subjectKind() === 'repository'
      ? `Modifier l'accès du dépôt ${this.label()}`
      : `Modifier l'accès de ${this.label()}`,
  )

  constructor() {
    // This modal is reused across every row, so re-seed the selected role each time it opens.
    effect(() => {
      if (this.isOpen()) {
        this.selectedRole.set(this.currentRole())
      }
    })
  }

  onRoleSelect(role: string): void {
    this.selectedRole.set(role as Role)
  }

  save(): void {
    this.roleChanged.emit(this.selectedRole())
  }

  revoke(): void {
    const subject =
      this.subjectKind() === 'repository' ? `du dépôt "${this.label()}"` : `de "${this.label()}"`
    if (!confirm(`Révoquer l'accès ${subject} ?`)) {
      return
    }
    this.revoked.emit()
  }
}
