import { ComponentFixture, TestBed } from '@angular/core/testing'
import { provideRouter } from '@angular/router'
import { of, throwError } from 'rxjs'
import { RegisterPage } from './register-page'
import { AuthService } from '../application/auth.service'

describe('RegisterPage', () => {
  let fixture: ComponentFixture<RegisterPage>
  let component: RegisterPage
  let authServiceSpy: { register: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    // This project's test runner (Angular's vitest-based unit-test builder) has no
    // `jasmine` global to provide `createSpyObj` — a hand-rolled `vi.fn()` spy stands in.
    authServiceSpy = {
      register: vi.fn(),
    }

    TestBed.configureTestingModule({
      imports: [RegisterPage],
      providers: [provideRouter([]), { provide: AuthService, useValue: authServiceSpy }],
    })
    fixture = TestBed.createComponent(RegisterPage)
    component = fixture.componentInstance
    fixture.detectChanges()
  })

  it('does not submit an invalid form', () => {
    component.submit()
    expect(authServiceSpy.register).not.toHaveBeenCalled()
  })

  it('routes to mandatory enrollment on a successful registration', () => {
    authServiceSpy.register.mockReturnValue(
      of({ mfaRequired: true, mfaToken: 'mfa-token-123', mfaSetupRequired: true }),
    )
    component.form.setValue({
      username: 'florian',
      email: 'florian@example.com',
      password: 'sup3r-s3cret!',
    })

    component.submit()

    expect(authServiceSpy.register).toHaveBeenCalledWith(
      'florian',
      'florian@example.com',
      'sup3r-s3cret!',
    )
    expect(component.mfaToken()).toBe('mfa-token-123')
  })

  it('surfaces a duplicate-username error', () => {
    authServiceSpy.register.mockReturnValue(
      throwError(() => ({ error: { error: 'username already taken' } })),
    )
    component.form.setValue({
      username: 'florian',
      email: 'florian@example.com',
      password: 'sup3r-s3cret!',
    })

    component.submit()

    expect(component.errorMessage()).toContain('nom d’utilisateur')
  })

  it('surfaces a registration-disabled error', () => {
    authServiceSpy.register.mockReturnValue(
      throwError(() => ({
        error: { error: 'public self-registration is not available on this organization' },
      })),
    )
    component.form.setValue({
      username: 'florian',
      email: 'florian@example.com',
      password: 'sup3r-s3cret!',
    })

    component.submit()

    expect(component.errorMessage()).toContain('pas disponible sur cette organisation')
  })

  it('surfaces an admin-disabled registration error distinctly from the org-level one', () => {
    authServiceSpy.register.mockReturnValue(
      throwError(() => ({
        error: { error: 'public self-registration is currently disabled' },
      })),
    )
    component.form.setValue({
      username: 'florian',
      email: 'florian@example.com',
      password: 'sup3r-s3cret!',
    })

    component.submit()

    expect(component.errorMessage()).toContain("désactivée par l'administrateur")
  })

  it('surfaces an invalid-username error', () => {
    authServiceSpy.register.mockReturnValue(
      throwError(() => ({ error: { error: 'invalid username: 1a' } })),
    )
    component.form.setValue({
      username: 'florian',
      email: 'florian@example.com',
      password: 'sup3r-s3cret!',
    })

    component.submit()

    expect(component.errorMessage()).toContain("Nom d'utilisateur invalide")
  })
})
