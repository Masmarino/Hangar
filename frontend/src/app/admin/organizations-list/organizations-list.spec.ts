import { ComponentFixture, TestBed } from '@angular/core/testing'
import { Router } from '@angular/router'
import { provideRouter } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationsList } from './organizations-list'
import { OrganizationsService } from '../application/organizations.service'

describe('OrganizationsList', () => {
  let fixture: ComponentFixture<OrganizationsList>
  let component: OrganizationsList
  let router: Router

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function setup(organizations: { id: string; slug: string; display_name: string; is_public: boolean }[]) {
    TestBed.configureTestingModule({
      imports: [OrganizationsList],
      providers: [
        provideRouter([]),
        {
          provide: OrganizationsService,
          useValue: { list: (_options?: unknown) => of(organizations) },
        },
      ],
    })
    fixture = TestBed.createComponent(OrganizationsList)
    component = fixture.componentInstance
    router = TestBed.inject(Router)
    fixture.detectChanges()
  }

  it('loads organizations on init', () => {
    setup([{ id: '1', slug: 'acme', display_name: 'Acme', is_public: false }])
    expect(component.organizations()).toEqual([{ id: '1', slug: 'acme', display_name: 'Acme', is_public: false }])
  })

  it('navigates to the organization detail page on row click', () => {
    setup([{ id: '1', slug: 'acme', display_name: 'Acme', is_public: false }])
    vi.spyOn(router, 'navigate')

    component.openDetail({ id: '1', slug: 'acme', display_name: 'Acme', is_public: false })

    expect(router.navigate).toHaveBeenCalledWith(['/admin/organizations', '1'])
  })
})
