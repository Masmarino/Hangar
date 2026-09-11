import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'

export interface BrandingPort {
  getLogo(organizationId?: string): Observable<Blob>
  uploadLogo(file: File, organizationId?: string): Observable<void>
  resetLogo(organizationId?: string): Observable<void>
  getFavicon(organizationId?: string): Observable<Blob>
  uploadFavicon(file: File, organizationId?: string): Observable<void>
  resetFavicon(organizationId?: string): Observable<void>
}

export const BRANDING_PORT = new InjectionToken<BrandingPort>('BrandingPort')
