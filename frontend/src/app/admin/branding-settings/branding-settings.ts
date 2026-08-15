import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core'
import { Button, Card } from '@masmarino/gabarit'
import { BrandingService } from '../application/branding.service'

// Kept in sync with MAX_ASSET_BYTES in branding.rs — rejects an oversized file here to save the full upload round-trip just to be told no.
const MAX_ASSET_BYTES = 2 * 1024 * 1024

@Component({
  selector: 'app-branding-settings',
  standalone: true,
  imports: [Button, Card],
  templateUrl: './branding-settings.html',
  styleUrl: './branding-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BrandingSettingsAdmin {
  private readonly brandingService = inject(BrandingService)

  // Cache-busting query param so the preview reloads after an upload or reset.
  readonly logoVersion = signal(0)
  readonly faviconVersion = signal(0)

  readonly logoPreviewUrl = computed(
    () => `${this.brandingService.logoUrl}?v=${this.logoVersion()}`,
  )

  readonly faviconPreviewUrl = computed(
    () => `${this.brandingService.faviconUrl}?v=${this.faviconVersion()}`,
  )

  readonly selectedLogoFile = signal<File | null>(null)
  readonly uploadingLogo = signal(false)
  readonly logoError = signal<string | null>(null)

  readonly selectedFaviconFile = signal<File | null>(null)
  readonly uploadingFavicon = signal(false)
  readonly faviconError = signal<string | null>(null)

  onLogoFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0] ?? null
    if (file && file.size > MAX_ASSET_BYTES) {
      this.selectedLogoFile.set(null)
      this.logoError.set('Le fichier dépasse la taille maximale de 2 Mo.')
      input.value = ''
      return
    }
    this.selectedLogoFile.set(file)
    this.logoError.set(null)
  }

  uploadLogo(): void {
    const file = this.selectedLogoFile()
    if (!file || this.uploadingLogo()) return
    this.uploadingLogo.set(true)
    this.logoError.set(null)
    this.brandingService.uploadLogo(file).subscribe({
      next: () => {
        this.uploadingLogo.set(false)
        this.selectedLogoFile.set(null)
        this.logoVersion.update((v) => v + 1)
      },
      error: (err) => {
        this.uploadingLogo.set(false)
        this.logoError.set(err?.error?.error ?? "Échec de l'import du logo.")
      },
    })
  }

  resetLogo(): void {
    if (this.uploadingLogo()) return
    this.uploadingLogo.set(true)
    this.logoError.set(null)
    this.brandingService.resetLogo().subscribe({
      next: () => {
        this.uploadingLogo.set(false)
        this.logoVersion.update((v) => v + 1)
      },
      error: () => {
        this.uploadingLogo.set(false)
        this.logoError.set('Échec de la réinitialisation du logo.')
      },
    })
  }

  onFaviconFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0] ?? null
    if (file && file.size > MAX_ASSET_BYTES) {
      this.selectedFaviconFile.set(null)
      this.faviconError.set('Le fichier dépasse la taille maximale de 2 Mo.')
      input.value = ''
      return
    }
    this.selectedFaviconFile.set(file)
    this.faviconError.set(null)
  }

  uploadFavicon(): void {
    const file = this.selectedFaviconFile()
    if (!file || this.uploadingFavicon()) return
    this.uploadingFavicon.set(true)
    this.faviconError.set(null)
    this.brandingService.uploadFavicon(file).subscribe({
      next: () => {
        this.uploadingFavicon.set(false)
        this.selectedFaviconFile.set(null)
        this.faviconVersion.update((v) => v + 1)
      },
      error: (err) => {
        this.uploadingFavicon.set(false)
        this.faviconError.set(err?.error?.error ?? "Échec de l'import du favicon.")
      },
    })
  }

  resetFavicon(): void {
    if (this.uploadingFavicon()) return
    this.uploadingFavicon.set(true)
    this.faviconError.set(null)
    this.brandingService.resetFavicon().subscribe({
      next: () => {
        this.uploadingFavicon.set(false)
        this.faviconVersion.update((v) => v + 1)
      },
      error: () => {
        this.uploadingFavicon.set(false)
        this.faviconError.set('Échec de la réinitialisation du favicon.')
      },
    })
  }
}
