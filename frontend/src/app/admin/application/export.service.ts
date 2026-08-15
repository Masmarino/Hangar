import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { ImportReport } from '../domain/export.entity'
import { EXPORT_PORT } from './export.port'

@Injectable({ providedIn: 'root' })
export class ExportService {
  private readonly port = inject(EXPORT_PORT)

  exportConfiguration(): Observable<Blob> {
    return this.port.exportConfiguration()
  }

  importConfiguration(file: File): Observable<ImportReport> {
    return this.port.importConfiguration(file)
  }
}
