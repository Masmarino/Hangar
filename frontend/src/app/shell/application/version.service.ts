import { Injectable, inject, signal } from '@angular/core'
import { VERSION_PORT } from './version.port'

@Injectable({ providedIn: 'root' })
export class VersionService {
  private readonly port = inject(VERSION_PORT)

  readonly version = signal<string | null>(null)
  private loaded = false

  /** Never fails loudly — the sidebar just omits the version if this doesn't resolve. */
  load(): void {
    if (this.loaded) {
      return
    }
    this.loaded = true
    this.port.load().subscribe({
      next: (response) => this.version.set(response.version),
      error: () => {
        this.loaded = false
      },
    })
  }
}
