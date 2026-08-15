import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { ImportReport } from '../domain/export.entity'

export interface ExportPort {
  exportConfiguration(): Observable<Blob>
  importConfiguration(file: File): Observable<ImportReport>
}

export const EXPORT_PORT = new InjectionToken<ExportPort>('ExportPort')
