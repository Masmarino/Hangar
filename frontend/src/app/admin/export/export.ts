import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import { Button, Card } from '@masmarino/gabarit'
import { ExportService } from '../application/export.service'
import { ImportReport } from '../domain/export.entity'
import { downloadBlob } from '../../shared/download'

@Component({
  selector: 'app-export',
  standalone: true,
  imports: [Button, Card],
  templateUrl: './export.html',
  styleUrl: './export.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ExportAdmin {
  private readonly exportService = inject(ExportService)

  readonly downloading = signal(false)
  readonly error = signal<string | null>(null)

  readonly selectedFile = signal<File | null>(null)
  readonly importing = signal(false)
  readonly importError = signal<string | null>(null)
  readonly importReport = signal<ImportReport | null>(null)

  downloadConfiguration(): void {
    this.error.set(null)
    this.downloading.set(true)
    this.exportService.exportConfiguration().subscribe({
      next: (blob) => {
        this.downloading.set(false)
        downloadBlob(blob, `hangar-config-${new Date().toISOString().slice(0, 10)}.json`)
      },
      error: () => {
        this.downloading.set(false)
        this.error.set("Échec de l'export de la configuration.")
      },
    })
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement
    this.selectedFile.set(input.files?.[0] ?? null)
    this.importReport.set(null)
    this.importError.set(null)
  }

  importConfiguration(): void {
    const file = this.selectedFile()
    if (!file || this.importing()) return
    if (
      !confirm(
        'Importer cette configuration ? Cette opération ne fonctionne que sur une instance vide (sans dépôt, sans autre utilisateur que le vôtre).',
      )
    ) {
      return
    }
    this.importing.set(true)
    this.importError.set(null)
    this.importReport.set(null)
    this.exportService.importConfiguration(file).subscribe({
      next: (report) => {
        this.importing.set(false)
        this.importReport.set(report)
      },
      error: (err) => {
        this.importing.set(false)
        this.importError.set(err?.error?.error ?? "Échec de l'import de la configuration.")
      },
    })
  }
}
