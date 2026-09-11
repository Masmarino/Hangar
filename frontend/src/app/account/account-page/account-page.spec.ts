import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { By } from '@angular/platform-browser'
import { DatePipe } from '@angular/common'
import { AccountPage } from './account-page'
import { MeService } from '../../shell/application/me.service'
import { ApiTokensList } from '../../tokens/api-tokens-list/api-tokens-list'
import { apiTokenProviders } from '../../tokens/infrastructure/api-token.providers'
import { mfaProviders } from '../infrastructure/mfa.providers'
import { meProviders } from '../../shell/infrastructure/me.providers'
import { authProviders } from '../../auth/infrastructure/auth.providers'
import { ToastService } from '../../shared/toast.service'

describe('AccountPage', () => {
  function render() {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...apiTokenProviders,
        ...mfaProviders,
        ...meProviders,
        ...authProviders,
      ],
    })
    const fixture = TestBed.createComponent(AccountPage)
    const me = TestBed.inject(MeService)
    me.username.set('florian')
    me.isSuperAdmin.set(true)
    me.createdAt.set('2026-01-01T00:00:00Z')
    fixture.detectChanges()
    const httpMock = TestBed.inject(HttpTestingController)
    // ApiTokensList loads its own tokens on init as a child component.
    httpMock.expectOne('/api/tokens').flush([])
    fixture.detectChanges()
    return { fixture, httpMock }
  }

  it('shows the username, super-admin status and member-since date', () => {
    const { fixture } = render()
    const text = fixture.nativeElement.textContent as string

    expect(text).toContain('florian')
    expect(text).toContain('Super-administrateur')
    const expectedDate = new DatePipe('en-US').transform('2026-01-01T00:00:00Z', 'medium')
    expect(text).toContain(expectedDate)
  })

  it('changes the password on submit and shows a success message', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'new-s3cret!',
      confirmPassword: 'new-s3cret!',
    })
    fixture.componentInstance.submit()

    const req = httpMock.expectOne('/api/me/password')
    expect(req.request.body).toEqual({
      current_password: 'old-s3cret!',
      new_password: 'new-s3cret!',
    })
    req.flush(null)
    fixture.detectChanges()

    expect(TestBed.inject(ToastService).toasts().at(-1)).toMatchObject({
      variant: 'success',
      message: 'Mot de passe changé avec succès.',
    })
  })

  it('shows an error and keeps the new/confirm fields when the server rejects the change', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'wrong',
      newPassword: 'new-s3cret!',
      confirmPassword: 'new-s3cret!',
    })
    fixture.componentInstance.submit()

    const req = httpMock.expectOne('/api/me/password')
    req.flush({ error: 'invalid credentials' }, { status: 400, statusText: 'Bad Request' })
    fixture.detectChanges()

    expect(TestBed.inject(ToastService).toasts().at(-1)).toMatchObject({
      variant: 'error',
      message: 'Mot de passe actuel incorrect ou nouveau mot de passe invalide.',
    })
    expect(fixture.componentInstance.form.controls.newPassword.value).toBe('new-s3cret!')
    expect(fixture.componentInstance.form.controls.confirmPassword.value).toBe('new-s3cret!')
    expect(fixture.componentInstance.form.controls.currentPassword.value).toBe('')
  })

  it('blocks submission client-side when new and confirm passwords do not match', () => {
    const { fixture, httpMock } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'new-s3cret!',
      confirmPassword: 'something-else!',
    })
    expect(fixture.componentInstance.form.invalid).toBe(true)

    fixture.componentInstance.submit()

    httpMock.expectNone('/api/me/password')
  })

  it('does not show a passwords-mismatch message before the confirm field is touched', () => {
    const { fixture } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'new-s3cret!',
      confirmPassword: 'something-else!',
    })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain(
      'Les mots de passe ne correspondent pas.',
    )
  })

  it('shows a passwords-mismatch message once the confirm field is touched', () => {
    const { fixture } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'new-s3cret!',
      confirmPassword: 'something-else!',
    })
    fixture.componentInstance.form.controls.confirmPassword.markAsTouched()
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Les mots de passe ne correspondent pas.')
  })

  it('clears the passwords-mismatch message once the values match again', () => {
    const { fixture } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'new-s3cret!',
      confirmPassword: 'something-else!',
    })
    fixture.componentInstance.form.controls.confirmPassword.markAsTouched()
    fixture.detectChanges()
    expect(fixture.nativeElement.textContent).toContain('Les mots de passe ne correspondent pas.')

    fixture.componentInstance.form.controls.confirmPassword.setValue('new-s3cret!')
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain(
      'Les mots de passe ne correspondent pas.',
    )
  })

  it('does not show a too-short message before the new-password field is touched', () => {
    const { fixture } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'short',
      confirmPassword: 'short',
    })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain(
      'Le mot de passe doit contenir au moins 8 caractères.',
    )
  })

  it('shows a too-short message once the new-password field is touched with fewer than 8 characters', () => {
    const { fixture } = render()

    fixture.componentInstance.form.setValue({
      currentPassword: 'old-s3cret!',
      newPassword: 'short',
      confirmPassword: 'short',
    })
    fixture.componentInstance.form.controls.newPassword.markAsTouched()
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain(
      'Le mot de passe doit contenir au moins 8 caractères.',
    )
  })

  it('embeds the API tokens list as a subsection', () => {
    const { fixture } = render()

    expect(fixture.debugElement.query(By.directive(ApiTokensList))).toBeTruthy()
  })
})
