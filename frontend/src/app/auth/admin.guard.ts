import { inject } from '@angular/core'
import { CanActivateFn, Router } from '@angular/router'
import { catchError, map, of } from 'rxjs'
import { MeService } from '../shell/application/me.service'

// Defense in depth — the backend already enforces this. Calls me.load() (not the signals directly) since a deep link can hit this guard before the shell loads them; forceRefresh so a mid-session demotion doesn't sail through on a cached flag.
export const adminGuard: CanActivateFn = () => {
  const me = inject(MeService)
  const router = inject(Router)

  return me.load({ forceRefresh: true }).pipe(
    map((response) => response.is_super_admin || router.createUrlTree(['/repositories'])),
    // any failure (not just 401) should fail closed rather than hang navigation
    catchError(() => of(router.createUrlTree(['/repositories']))),
  )
}
