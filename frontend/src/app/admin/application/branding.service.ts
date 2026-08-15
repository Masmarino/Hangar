import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { BRANDING_PORT } from './branding.port'

/** `logoUrl`/`faviconUrl` always resolve — the operator's upload, or the default. */
@Injectable({ providedIn: 'root' })
export class BrandingService {
  private readonly port = inject(BRANDING_PORT)

  readonly logoUrl = '/api/branding/logo'
  readonly faviconUrl = '/api/branding/favicon'

  uploadLogo(file: File): Observable<void> {
    return this.port.uploadLogo(file)
  }

  resetLogo(): Observable<void> {
    return this.port.resetLogo()
  }

  uploadFavicon(file: File): Observable<void> {
    return this.port.uploadFavicon(file)
  }

  resetFavicon(): Observable<void> {
    return this.port.resetFavicon()
  }
}
