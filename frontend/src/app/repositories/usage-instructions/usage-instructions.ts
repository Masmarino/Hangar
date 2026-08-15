import { DOCUMENT } from '@angular/common'
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core'
import { RouterLink } from '@angular/router'
import { RepositorySummary } from '../domain/repository.entity'

@Component({
  selector: 'app-usage-instructions',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './usage-instructions.html',
  styleUrl: './usage-instructions.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UsageInstructions {
  private readonly document = inject(DOCUMENT)

  readonly repository = input.required<RepositorySummary>()

  readonly host = this.document.location.host
  readonly origin = this.document.location.origin
  readonly isHosted = computed(() => this.repository().repo_type === 'hosted')
}
