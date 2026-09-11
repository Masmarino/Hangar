import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Tooltip } from '@masmarino/gabarit'
import { ApiTokensAdmin } from './api-tokens'
import { adminProviders } from '../infrastructure/admin.providers'
import { ToastService } from '../../shared/toast.service'

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(ApiTokensAdmin)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  return { fixture, httpMock }
}

function flushTokens(httpMock: HttpTestingController, tokens: unknown[]) {
  httpMock.expectOne('/api/admin/tokens').flush(tokens)
}

describe('ApiTokensAdmin', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows an empty message when there are no active tokens', () => {
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Aucun jeton actif.')
  })

  it('splits tokens into active and revoked sections', () => {
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [
      {
        id: 't1',
        user_id: 'u1',
        username: 'florian',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
      {
        id: 't2',
        user_id: 'u2',
        username: 'bob',
        label: 'ci',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: '2026-01-02T00:00:00Z',
      },
    ])
    fixture.detectChanges()

    expect(fixture.componentInstance.activeTokens().map((t) => t.id)).toEqual(['t1'])
    expect(fixture.componentInstance.revokedTokens().map((t) => t.id)).toEqual(['t2'])
    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('Jetons actifs')
    expect(text).toContain('Jetons révoqués')
    expect(text).toContain('florian')
    expect(text).toContain('bob')
  })

  it('does not show the revoked section when there are no revoked tokens', () => {
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [
      {
        id: 't1',
        user_id: 'u1',
        username: 'florian',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Jetons révoqués')
  })

  it('revokes a token after confirmation and reloads the list', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [
      {
        id: 't1',
        user_id: 'u1',
        username: 'florian',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ])
    fixture.detectChanges()

    const button: HTMLButtonElement = fixture.nativeElement.querySelector(
      '.api-tokens__actions button',
    )
    button.click()

    expect(window.confirm).toHaveBeenCalledWith('Révoquer le jeton « laptop » de florian ?')
    const revokeReq = httpMock.expectOne('/api/admin/tokens/t1')
    expect(revokeReq.request.method).toBe('DELETE')
    revokeReq.flush(null)

    flushTokens(httpMock, [])

    const toastService = TestBed.inject(ToastService)
    expect(toastService.toasts().at(-1)).toMatchObject({
      variant: 'success',
      message: 'Jeton « laptop » révoqué.',
    })
  })

  it('does not revoke when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [
      {
        id: 't1',
        user_id: 'u1',
        username: 'florian',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ])
    fixture.detectChanges()

    const button: HTMLButtonElement = fixture.nativeElement.querySelector(
      '.api-tokens__actions button',
    )
    button.click()

    httpMock.expectNone('/api/admin/tokens/t1')
  })

  it('re-fetches when organizationId changes to a different organization — the component is reused, not recreated, across a super-admin switching organizations', () => {
    const { fixture, httpMock } = render()
    httpMock.expectOne('/api/admin/tokens').flush([])
    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
    httpMock.expectOne('/api/admin/tokens?organization_id=org-1').flush([
      {
        id: 't1',
        user_id: 'u1',
        username: 'org1-user',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ])
    fixture.detectChanges()
    expect(fixture.nativeElement.textContent).toContain('org1-user')

    fixture.componentRef.setInput('organizationId', 'org-2')
    fixture.detectChanges()
    httpMock.expectOne('/api/admin/tokens?organization_id=org-2').flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('org1-user')
  })

  it('explains via a tooltip that revoking a token is immediate and permanent', () => {
    const { fixture, httpMock } = render()
    flushTokens(httpMock, [
      {
        id: 't1',
        user_id: 'u1',
        username: 'florian',
        label: 'laptop',
        created_at: '2026-01-01T00:00:00Z',
        last_used_at: null,
        revoked_at: null,
      },
    ])
    fixture.detectChanges()

    const tooltip = fixture.debugElement.query(By.directive(Tooltip))

    expect((tooltip.componentInstance as Tooltip).text()).toBe(
      'Le jeton cessera immédiatement de fonctionner, définitivement.',
    )
  })
})
