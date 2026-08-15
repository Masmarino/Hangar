import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { provideRouter } from '@angular/router'
import { provideTransloco } from '@jsverse/transloco'
import { CreateUserModal } from './create-user-modal'
import { userProviders } from '../infrastructure/user.providers'

describe('CreateUserModal', () => {
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CreateUserModal],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideTransloco({
          config: { availableLangs: ['fr'], defaultLang: 'fr', prodMode: false },
        }),
        ...userProviders,
      ],
    })
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('renders a control bound to the isSuperAdmin form control', () => {
    const fixture = TestBed.createComponent(CreateUserModal)
    fixture.detectChanges()

    const checkbox: HTMLInputElement | null =
      fixture.nativeElement.querySelector('input[type="checkbox"]')
    expect(checkbox).not.toBeNull()

    checkbox!.checked = true
    checkbox!.dispatchEvent(new Event('change'))
    fixture.detectChanges()

    expect(fixture.componentInstance.form.getRawValue().isSuperAdmin).toBe(true)
  })

  it('posts is_super_admin: true when the checkbox is ticked', () => {
    const fixture = TestBed.createComponent(CreateUserModal)
    fixture.detectChanges()

    fixture.componentInstance.form.patchValue({ username: 'florian', email: 'florian@example.com' })
    const checkbox: HTMLInputElement = fixture.nativeElement.querySelector('input[type="checkbox"]')
    checkbox.checked = true
    checkbox.dispatchEvent(new Event('change'))
    fixture.detectChanges()

    fixture.componentInstance.submit()

    const request = httpMock.expectOne('/api/users')
    expect(request.request.body).toEqual({
      username: 'florian',
      email: 'florian@example.com',
      is_super_admin: true,
    })
    request.flush({
      id: 'user-1',
      username: 'florian',
      is_super_admin: true,
      email: 'florian@example.com',
      invitation_pending: true,
    })
  })

  it('posts is_super_admin: false when the checkbox is left untouched', () => {
    const fixture = TestBed.createComponent(CreateUserModal)
    fixture.detectChanges()

    fixture.componentInstance.form.patchValue({ username: 'florian', email: 'florian@example.com' })
    fixture.componentInstance.submit()

    const request = httpMock.expectOne('/api/users')
    expect(request.request.body).toEqual({
      username: 'florian',
      email: 'florian@example.com',
      is_super_admin: false,
    })
    request.flush({
      id: 'user-1',
      username: 'florian',
      is_super_admin: false,
      email: 'florian@example.com',
      invitation_pending: true,
    })
  })
})
