import { TestBed } from '@angular/core/testing'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationContextBanner } from './organization-context-banner'
import { OrganizationsService } from '../application/organizations.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationContextBanner', () => {
  function render(isSuperAdmin: boolean) {
    const organizationsServiceStub = {
      get: () => of({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' }),
    }
    const meServiceStub = { isSuperAdmin: () => isSuperAdmin }
    TestBed.configureTestingModule({
      imports: [OrganizationContextBanner],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceStub },
        { provide: MeService, useValue: meServiceStub },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { paramMap: convertToParamMap({ id: 'org-1' }) } },
        },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationContextBanner)
    fixture.detectChanges()
    return fixture
  }

  it('names the organization from the route', () => {
    const fixture = render(false)

    expect(fixture.nativeElement.textContent).toContain('Acme Corp')
    expect(fixture.nativeElement.textContent).toContain('acme')
  })

  it('does not show the super-admin caution for a regular organization admin', () => {
    const fixture = render(false)

    expect(fixture.nativeElement.textContent).not.toContain('super-admin')
  })

  it('shows the domain-mismatch caution for a super-admin', () => {
    const fixture = render(true)

    expect(fixture.nativeElement.textContent).toContain('super-admin')
  })

  it('uses the wide .container by default, so it aligns with a sibling table or dashboard page', () => {
    const fixture = render(false)

    expect(fixture.nativeElement.querySelector('.container')).toBeTruthy()
    expect(fixture.nativeElement.querySelector('.form-container')).toBeFalsy()
  })

  it('uses the narrower .form-container when told it sits above a settings form, so the two align', () => {
    const fixture = render(false)
    fixture.componentRef.setInput('narrow', true)
    fixture.detectChanges()

    expect(fixture.nativeElement.querySelector('.form-container')).toBeTruthy()
    expect(fixture.nativeElement.querySelector('.container')).toBeFalsy()
  })
})
