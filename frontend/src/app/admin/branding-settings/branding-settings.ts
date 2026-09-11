import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  inject,
  input,
  signal,
  type WritableSignal,
} from '@angular/core'
import { Button, Card, Tooltip } from '@masmarino/gabarit'
import { BrandingService } from '../application/branding.service'
import { ToastService } from '../../shared/toast.service'

// Kept in sync with MAX_ASSET_BYTES in branding.rs — rejects an oversized file here to save the full upload round-trip just to be told no.
const MAX_ASSET_BYTES = 2 * 1024 * 1024

@Component({
  selector: 'app-branding-settings',
  standalone: true,
  imports: [Button, Card, Tooltip],
  templateUrl: './branding-settings.html',
  styleUrl: './branding-settings.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BrandingSettingsAdmin {
  private readonly brandingService = inject(BrandingService)
  private readonly destroyRef = inject(DestroyRef)
  private readonly toastService = inject(ToastService)

  /** Set only when embedded in an organization's own admin page — scopes the preview/upload/reset to it. */
  readonly organizationId = input<string | undefined>(undefined)

  // Object URLs from the authenticated preview endpoint, not the public host-resolved one.
  readonly logoPreviewUrl = signal<string | null>(null)
  readonly faviconPreviewUrl = signal<string | null>(null)

  readonly selectedLogoFile = signal<File | null>(null)
  readonly uploadingLogo = signal(false)
  readonly logoError = signal<string | null>(null)

  readonly selectedFaviconFile = signal<File | null>(null)
  readonly uploadingFavicon = signal(false)
  readonly faviconError = signal<string | null>(null)

  // effect(), not ngOnInit — this component is reused across organizations on the same route.
  constructor() {
    effect(() => {
      this.organizationId()
      this.reloadLogo()
      this.reloadFavicon()
    })
    this.destroyRef.onDestroy(() => {
      this.revokePreview(this.logoPreviewUrl())
      this.revokePreview(this.faviconPreviewUrl())
    })
  }

  private reloadLogo(): void {
    this.brandingService
      .getLogo(this.organizationId())
      .subscribe((blob) => this.setPreview(this.logoPreviewUrl, blob))
  }

  private reloadFavicon(): void {
    this.brandingService
      .getFavicon(this.organizationId())
      .subscribe((blob) => this.setPreview(this.faviconPreviewUrl, blob))
  }

  private setPreview(target: WritableSignal<string | null>, blob: Blob): void {
    const previous = target()
    target.set(URL.createObjectURL(blob))
    this.revokePreview(previous)
  }

  private revokePreview(url: string | null): void {
    if (url) {
      URL.revokeObjectURL(url)
    }
  }

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
    this.brandingService.uploadLogo(file, this.organizationId()).subscribe({
      next: () => {
        this.uploadingLogo.set(false)
        this.selectedLogoFile.set(null)
        this.reloadLogo()
        this.toastService.success('Logo importé.')
      },
      error: (err) => {
        this.uploadingLogo.set(false)
        this.toastService.error(err?.error?.error ?? "Échec de l'import du logo.")
      },
    })
  }

  resetLogo(): void {
    if (this.uploadingLogo()) return
    this.uploadingLogo.set(true)
    this.logoError.set(null)
    this.brandingService.resetLogo(this.organizationId()).subscribe({
      next: () => {
        this.uploadingLogo.set(false)
        this.reloadLogo()
        this.toastService.success('Logo réinitialisé.')
      },
      error: () => {
        this.uploadingLogo.set(false)
        this.toastService.error('Échec de la réinitialisation du logo.')
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
    this.brandingService.uploadFavicon(file, this.organizationId()).subscribe({
      next: () => {
        this.uploadingFavicon.set(false)
        this.selectedFaviconFile.set(null)
        this.reloadFavicon()
        this.toastService.success('Favicon importé.')
      },
      error: (err) => {
        this.uploadingFavicon.set(false)
        this.toastService.error(err?.error?.error ?? "Échec de l'import du favicon.")
      },
    })
  }

  resetFavicon(): void {
    if (this.uploadingFavicon()) return
    this.uploadingFavicon.set(true)
    this.faviconError.set(null)
    this.brandingService.resetFavicon(this.organizationId()).subscribe({
      next: () => {
        this.uploadingFavicon.set(false)
        this.reloadFavicon()
        this.toastService.success('Favicon réinitialisé.')
      },
      error: () => {
        this.uploadingFavicon.set(false)
        this.toastService.error('Échec de la réinitialisation du favicon.')
      },
    })
  }
}
