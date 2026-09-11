import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { BrandingPort } from '../application/branding.port'

function orgParams(organizationId?: string): Record<string, string> {
  return organizationId ? { organization_id: organizationId } : {}
}

@Injectable()
export class HttpBrandingAdapter implements BrandingPort {
  private readonly http = inject(HttpClient)

  getLogo(organizationId?: string): Observable<Blob> {
    return this.http.get('/api/admin/branding/logo', {
      params: orgParams(organizationId),
      responseType: 'blob',
    })
  }

  uploadLogo(file: File, organizationId?: string): Observable<void> {
    return this.http.put<void>('/api/admin/branding/logo', file, {
      params: orgParams(organizationId),
    })
  }

  resetLogo(organizationId?: string): Observable<void> {
    return this.http.delete<void>('/api/admin/branding/logo', { params: orgParams(organizationId) })
  }

  getFavicon(organizationId?: string): Observable<Blob> {
    return this.http.get('/api/admin/branding/favicon', {
      params: orgParams(organizationId),
      responseType: 'blob',
    })
  }

  uploadFavicon(file: File, organizationId?: string): Observable<void> {
    return this.http.put<void>('/api/admin/branding/favicon', file, {
      params: orgParams(organizationId),
    })
  }

  resetFavicon(organizationId?: string): Observable<void> {
    return this.http.delete<void>('/api/admin/branding/favicon', {
      params: orgParams(organizationId),
    })
  }
}
