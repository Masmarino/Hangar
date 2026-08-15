import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  effect,
  inject,
  output,
  signal,
} from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import {
  FormControl,
  FormGroup,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms'
import { Button, GbtInput, Modal, Select, type SelectOption } from '@masmarino/gabarit'
import { RepositoriesService } from '../application/repositories.service'
import { RepositoryFormat, RepositorySummary, RepositoryType } from '../domain/repository.entity'

const FORMAT_OPTIONS: SelectOption<RepositoryFormat>[] = [
  { value: 'npm', label: 'npm' },
  { value: 'docker', label: 'docker' },
]

const REPO_TYPE_OPTIONS: SelectOption<RepositoryType>[] = [
  { value: 'hosted', label: 'hosted' },
  { value: 'proxy', label: 'proxy' },
  { value: 'group', label: 'group' },
]

const BYTES_PER_MB = 1024 * 1024

@Component({
  selector: 'app-create-repository-modal',
  standalone: true,
  imports: [ReactiveFormsModule, FormsModule, Modal, GbtInput, Select, Button],
  templateUrl: './create-repository-modal.html',
  styleUrl: './create-repository-modal.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CreateRepositoryModal implements OnInit {
  private readonly repositoriesService = inject(RepositoriesService)

  readonly created = output<void>()
  readonly cancelled = output<void>()

  readonly formatOptions = FORMAT_OPTIONS
  readonly repoTypeOptions = REPO_TYPE_OPTIONS

  readonly form = new FormGroup({
    name: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    format: new FormControl<RepositoryFormat>('npm', { nonNullable: true }),
    repoType: new FormControl<RepositoryType>('hosted', { nonNullable: true }),
    remoteUrl: new FormControl('', { nonNullable: true }),
    remoteUsername: new FormControl('', { nonNullable: true }),
    remotePassword: new FormControl('', { nonNullable: true }),
    quotaMb: new FormControl('', { nonNullable: true }),
    retentionKeepLastN: new FormControl('', { nonNullable: true }),
  })

  // Zoneless change detection only re-renders on signal changes, so this needs to be
  // driven from valueChanges rather than read directly inside a computed().
  private readonly format = toSignal(this.form.controls.format.valueChanges, {
    initialValue: this.form.controls.format.value,
  })
  private readonly repoType = toSignal(this.form.controls.repoType.valueChanges, {
    initialValue: this.form.controls.repoType.value,
  })
  readonly isProxy = computed(() => this.repoType() === 'proxy')
  readonly isGroup = computed(() => this.repoType() === 'group')

  readonly allRepositories = signal<RepositorySummary[]>([])
  readonly selectedMemberId = signal('')
  readonly groupMembers = signal<RepositorySummary[]>([])

  readonly availableMemberOptions = computed<SelectOption<string>[]>(() => {
    const chosen = new Set(this.groupMembers().map((r) => r.id))
    return this.allRepositories()
      .filter((r) => r.format === this.format() && !chosen.has(r.id))
      .map((r) => ({ value: r.id, label: r.name }))
  })

  constructor() {
    // A group can only aggregate same-format repositories, so drop stale picks on format change.
    effect(() => {
      this.format()
      this.groupMembers.set([])
    })
  }

  ngOnInit(): void {
    this.repositoriesService.list().subscribe((repos) => this.allRepositories.set(repos))
  }

  addMember(): void {
    const id = this.selectedMemberId()
    const repo = this.allRepositories().find((r) => r.id === id)
    if (!repo) {
      return
    }
    this.groupMembers.update((members) => [...members, repo])
    this.selectedMemberId.set('')
  }

  removeMember(id: string): void {
    this.groupMembers.update((members) => members.filter((m) => m.id !== id))
  }

  moveMemberUp(index: number): void {
    if (index <= 0) {
      return
    }
    this.groupMembers.update((members) => {
      const reordered = [...members]
      ;[reordered[index - 1], reordered[index]] = [reordered[index], reordered[index - 1]]
      return reordered
    })
  }

  moveMemberDown(index: number): void {
    this.groupMembers.update((members) => {
      if (index >= members.length - 1) {
        return members
      }
      const reordered = [...members]
      ;[reordered[index + 1], reordered[index]] = [reordered[index], reordered[index + 1]]
      return reordered
    })
  }

  get quotaError(): string | null {
    const raw = this.form.controls.quotaMb.value.trim()
    if (raw === '') {
      return null
    }
    const mb = Number(raw)
    return Number.isFinite(mb) && mb >= 0
      ? null
      : 'Doit être un nombre positif (ou vide pour illimité).'
  }

  get retentionError(): string | null {
    const raw = this.form.controls.retentionKeepLastN.value.trim()
    if (raw === '') {
      return null
    }
    const n = Number(raw)
    return Number.isInteger(n) && n >= 1
      ? null
      : 'Doit être un entier positif (ou vide pour désactiver).'
  }

  get hasErrors(): boolean {
    return this.form.invalid || this.quotaError !== null || this.retentionError !== null
  }

  readonly creating = signal(false)

  submit(): void {
    if (this.hasErrors || this.creating()) {
      return
    }
    this.creating.set(true)
    const {
      name,
      format,
      repoType,
      remoteUrl,
      remoteUsername,
      remotePassword,
      quotaMb,
      retentionKeepLastN,
    } = this.form.getRawValue()
    const quotaBytes = quotaMb.trim() === '' ? null : Math.round(Number(quotaMb) * BYTES_PER_MB)
    const retentionKeepLastNValue =
      retentionKeepLastN.trim() === '' ? null : Number(retentionKeepLastN)

    this.repositoriesService
      .create(name, format, repoType, repoType === 'proxy' ? remoteUrl : null, {
        remoteUsername:
          repoType === 'proxy' && remoteUsername.trim() !== '' ? remoteUsername : null,
        remotePassword:
          repoType === 'proxy' && remotePassword.trim() !== '' ? remotePassword : null,
        groupMembers: repoType === 'group' ? this.groupMembers().map((m) => m.id) : [],
        quotaBytes,
        retentionKeepLastN: retentionKeepLastNValue,
      })
      .subscribe({
        next: () => {
          this.creating.set(false)
          this.created.emit()
        },
        error: () => this.creating.set(false),
      })
  }
}
