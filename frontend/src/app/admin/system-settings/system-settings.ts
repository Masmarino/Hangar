import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { Button, Card, Checkbox, GbtInput } from '@masmarino/gabarit'
import { SystemSettingsService } from '../application/system-settings.service'

interface FieldSpec {
  key: 'maxLoginAttempts' | 'loginAttemptWindowSeconds' | 'sessionTtlHours'
  min: number
  max: number
  label: string
}

// Mirrors the backend's validation in UpdateSystemSettingsUseCase, kept in sync by hand, so the form can reject an out-of-range value before a round trip.
const FIELDS: FieldSpec[] = [
  { key: 'maxLoginAttempts', min: 1, max: 1000, label: 'Tentatives de connexion max' },
  { key: 'loginAttemptWindowSeconds', min: 1, max: 86_400, label: 'Fenêtre de blocage (secondes)' },
  { key: 'sessionTtlHours', min: 1, max: 720, label: 'Durée de session (heures)' },
]

@Component({
  selector: 'app-system-settings',
  standalone: true,
  imports: [Button, Card, GbtInput, Checkbox, FormsModule],
  templateUrl: './system-settings.html',
  styleUrl: './system-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SystemSettingsAdmin implements OnInit {
  private readonly settingsService = inject(SystemSettingsService)

  readonly fields = FIELDS
  readonly maxLoginAttempts = signal('')
  readonly loginAttemptWindowSeconds = signal('')
  readonly sessionTtlHours = signal('')
  readonly registrationEnabled = signal(true)
  readonly loading = signal(true)
  readonly saving = signal(false)
  readonly saved = signal(false)
  readonly errorMessage = signal<string | null>(null)

  ngOnInit(): void {
    this.settingsService.get().subscribe((settings) => {
      this.maxLoginAttempts.set(String(settings.max_login_attempts))
      this.loginAttemptWindowSeconds.set(String(settings.login_attempt_window_seconds))
      this.sessionTtlHours.set(String(settings.session_ttl_hours))
      this.registrationEnabled.set(settings.registration_enabled)
      this.loading.set(false)
    })
  }

  value(key: FieldSpec['key']): string {
    return this[key]()
  }

  setValue(key: FieldSpec['key'], value: string): void {
    this[key].set(value)
  }

  // Errors stay hidden until a save is attempted — same shape as smtp-settings.ts.
  readonly attemptedSave = signal(false)

  private rawFieldError(field: FieldSpec): string | null {
    const parsed = Number(this.value(field.key))
    if (this.value(field.key).trim() === '' || !Number.isInteger(parsed)) {
      return 'Doit être un nombre entier.'
    }
    if (parsed < field.min || parsed > field.max) {
      return `Doit être entre ${field.min} et ${field.max}.`
    }
    return null
  }

  fieldError(field: FieldSpec): string | null {
    return this.attemptedSave() ? this.rawFieldError(field) : null
  }

  readonly hasErrors = computed(
    () => this.attemptedSave() && this.fields.some((f) => this.rawFieldError(f) !== null),
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
        max_login_attempts: Number(this.maxLoginAttempts()),
        login_attempt_window_seconds: Number(this.loginAttemptWindowSeconds()),
        session_ttl_hours: Number(this.sessionTtlHours()),
        registration_enabled: this.registrationEnabled(),
      })
      .subscribe({
        next: () => {
          this.saving.set(false)
          this.saved.set(true)
        },
        error: () => {
          this.saving.set(false)
          this.errorMessage.set('Échec de la mise à jour des paramètres.')
        },
      })
  }
}
