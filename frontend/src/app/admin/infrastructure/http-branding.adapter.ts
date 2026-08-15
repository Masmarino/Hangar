import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { BrandingPort } from '../application/branding.port'

@Injectable()
export class HttpBrandingAdapter implements BrandingPort {
  private readonly http = inject(HttpClient)

  uploadLogo(file: File): Observable<void> {
    return this.http.put<void>('/api/admin/branding/logo', file)
  }

  resetLogo(): Observable<void> {
    return this.http.delete<void>('/api/admin/branding/logo')
  }

  uploadFavicon(file: File): Observable<void> {
    return this.http.put<void>('/api/admin/branding/favicon', file)
  }

  resetFavicon(): Observable<void> {
    return this.http.delete<void>('/api/admin/branding/favicon')
  }
}
