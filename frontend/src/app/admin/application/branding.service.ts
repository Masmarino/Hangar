import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { BRANDING_PORT } from './branding.port'

@Injectable({ providedIn: 'root' })
export class BrandingService {
  private readonly port = inject(BRANDING_PORT)

  getLogo(organizationId?: string): Observable<Blob> {
    return this.port.getLogo(organizationId)
  }

  uploadLogo(file: File, organizationId?: string): Observable<void> {
    return this.port.uploadLogo(file, organizationId)
  }

  resetLogo(organizationId?: string): Observable<void> {
    return this.port.resetLogo(organizationId)
  }

  getFavicon(organizationId?: string): Observable<Blob> {
    return this.port.getFavicon(organizationId)
  }

  uploadFavicon(file: File, organizationId?: string): Observable<void> {
    return this.port.uploadFavicon(file, organizationId)
  }

  resetFavicon(organizationId?: string): Observable<void> {
    return this.port.resetFavicon(organizationId)
  }
}
