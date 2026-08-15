import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable, from, switchMap } from 'rxjs'
import { ImportReport } from '../domain/export.entity'
import { ExportPort } from '../application/export.port'

@Injectable()
export class HttpExportAdapter implements ExportPort {
  private readonly http = inject(HttpClient)

  /** Fetched via HttpClient, not a plain link, so the Bearer auth header attaches. */
  exportConfiguration(): Observable<Blob> {
    return this.http.get('/api/admin/export/configuration', { responseType: 'blob' })
  }

  importConfiguration(file: File): Observable<ImportReport> {
    return from(file.text()).pipe(
      switchMap((text) =>
        this.http.post<ImportReport>('/api/admin/import/configuration', JSON.parse(text)),
      ),
    )
  }
}
