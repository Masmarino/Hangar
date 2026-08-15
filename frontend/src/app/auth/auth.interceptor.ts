import { inject } from '@angular/core'
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http'
import { Router } from '@angular/router'
import { catchError, throwError } from 'rxjs'
import { AuthService } from './application/auth.service'

const LOGIN_URL = '/api/auth/login'

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  // Both must be injected here, synchronously: the catchError callback below runs
  // later, outside the injection context.
  const auth = inject(AuthService)
  const router = inject(Router)

  const token = auth.token()
  const authorizedReq = token
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req

  return next(authorizedReq).pipe(
    catchError((error: unknown) => {
      // A 401 elsewhere means the token expired or was invalidated — log out and redirect.
      // The login endpoint itself is excluded, or a wrong password would loop onto itself.
      if (
        error instanceof HttpErrorResponse &&
        error.status === 401 &&
        !req.url.endsWith(LOGIN_URL)
      ) {
        auth.logout()
        router.navigateByUrl('/login')
      }
      return throwError(() => error)
    }),
  )
}
