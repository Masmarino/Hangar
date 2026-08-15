import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { MeResponse } from '../domain/me.entity'
import { MePort } from '../application/me.port'

@Injectable()
export class HttpMeAdapter implements MePort {
  private readonly http = inject(HttpClient)

  load(): Observable<MeResponse> {
    return this.http.get<MeResponse>('/api/me')
  }

  changePassword(currentPassword: string, newPassword: string): Observable<void> {
    return this.http.put<void>('/api/me/password', {
      current_password: currentPassword,
      new_password: newPassword,
    })
  }
}
