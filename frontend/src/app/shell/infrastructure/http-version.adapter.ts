import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { VersionResponse } from '../domain/version.entity'
import { VersionPort } from '../application/version.port'

@Injectable()
export class HttpVersionAdapter implements VersionPort {
  private readonly http = inject(HttpClient)

  load(): Observable<VersionResponse> {
    return this.http.get<VersionResponse>('/api/version')
  }
}
