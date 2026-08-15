import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'

export interface BrandingPort {
  uploadLogo(file: File): Observable<void>
  resetLogo(): Observable<void>
  uploadFavicon(file: File): Observable<void>
  resetFavicon(): Observable<void>
}

export const BRANDING_PORT = new InjectionToken<BrandingPort>('BrandingPort')
