import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { CreateOrganizationModal } from './create-organization-modal'
import { organizationsProviders } from '../infrastructure/organizations.providers'

describe('CreateOrganizationModal', () => {
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CreateOrganizationModal],
      providers: [provideHttpClient(), provideHttpClientTesting(), ...organizationsProviders],
    })
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('posts the slug and display name on submit', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()

    fixture.componentInstance.form.setValue({ slug: 'acme', displayName: 'Acme Corp' })
    fixture.componentInstance.submit()

    const request = httpMock.expectOne('/api/organizations')
    expect(request.request.body).toEqual({ slug: 'acme', display_name: 'Acme Corp' })
    request.flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })
  })

  it('emits created after a successful submit', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()
    let created = false
    fixture.componentInstance.created.subscribe(() => (created = true))

    fixture.componentInstance.form.setValue({ slug: 'acme', displayName: 'Acme Corp' })
    fixture.componentInstance.submit()
    httpMock.expectOne('/api/organizations').flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })

    expect(created).toBe(true)
  })

  it('does not submit an invalid form', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()

    fixture.componentInstance.submit()

    httpMock.expectNone('/api/organizations')
  })
})
