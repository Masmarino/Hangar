import { ComponentFixture, TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of, throwError } from 'rxjs'
import { OrganizationDetail } from './organization-detail'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationMembersService } from '../application/organization-members.service'
import { OrganizationMembers } from '../organization-members/organization-members'
import { PageTitleService } from '../../shell/page-title.service'

describe('OrganizationDetail', () => {
  let fixture: ComponentFixture<OrganizationDetail>
  let component: OrganizationDetail
  let organizationsServiceSpy: {
    get: ReturnType<typeof vi.fn>
    getIdentityProvider: ReturnType<typeof vi.fn>
    setLdapIdentityProvider: ReturnType<typeof vi.fn>
    setOidcIdentityProvider: ReturnType<typeof vi.fn>
    clearIdentityProvider: ReturnType<typeof vi.fn>
  }

  function setup() {
    // This project's test runner (Angular's vitest-based unit-test builder) has no
    // `jasmine` global to provide `createSpyObj` — hand-rolled `vi.fn()` spies stand in.
    organizationsServiceSpy = {
      get: vi.fn(),
      getIdentityProvider: vi.fn(),
      setLdapIdentityProvider: vi.fn(),
      setOidcIdentityProvider: vi.fn(),
      clearIdentityProvider: vi.fn(),
    }
    organizationsServiceSpy.get.mockReturnValue(
      of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }),
    )
    organizationsServiceSpy.getIdentityProvider.mockReturnValue(of({ type: null }))

    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: vi.fn() } } },
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) },
        },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()
  }

  it('loads the organization and its identity provider on init', () => {
    setup()
    expect(organizationsServiceSpy.get).toHaveBeenCalledWith('org-1')
    expect(organizationsServiceSpy.getIdentityProvider).toHaveBeenCalledWith('org-1')
    expect(component.organization()?.display_name).toBe('Acme')
    expect(component.identityProviderConfigured()).toBe(false)
  })

  it('shows an error and stops loading when fetching the organization fails', () => {
    organizationsServiceSpy = {
      get: vi.fn(),
      getIdentityProvider: vi.fn(),
      setLdapIdentityProvider: vi.fn(),
      setOidcIdentityProvider: vi.fn(),
      clearIdentityProvider: vi.fn(),
    }
    organizationsServiceSpy.get.mockReturnValue(throwError(() => new Error('load failed')))
    organizationsServiceSpy.getIdentityProvider.mockReturnValue(of({ type: null }))
    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: vi.fn() } } },
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()

    expect(component.loading()).toBe(false)
    expect(component.errorMessage()).toBe("Échec du chargement de l'organisation.")
    expect(component.organization()).toBeNull()
  })

  it('reflects an existing LDAP configuration', () => {
    organizationsServiceSpy = {
      get: vi.fn(),
      getIdentityProvider: vi.fn(),
      setLdapIdentityProvider: vi.fn(),
      setOidcIdentityProvider: vi.fn(),
      clearIdentityProvider: vi.fn(),
    }
    organizationsServiceSpy.get.mockReturnValue(
      of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }),
    )
    organizationsServiceSpy.getIdentityProvider.mockReturnValue(
      of({
        type: 'ldap',
        server_url: 'ldap://dc.corp.example:389',
        bind_dn: 'cn=service,dc=corp,dc=example',
        bind_password_set: true,
        user_search_base: 'ou=people,dc=corp,dc=example',
        user_search_filter: '(uid={username})',
        email_attribute: 'mail',
      }),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: vi.fn() } } },
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()

    expect(component.identityProviderConfigured()).toBe(true)
    expect(component.serverUrl()).toBe('ldap://dc.corp.example:389')
    expect(component.bindPasswordSet()).toBe(true)
  })

  it('saves the LDAP configuration', () => {
    setup()
    organizationsServiceSpy.setLdapIdentityProvider.mockReturnValue(of(undefined))
    component.serverUrl.set('ldap://dc.corp.example:389')
    component.bindDn.set('cn=service,dc=corp,dc=example')
    component.bindPassword.set('s3cret!')
    component.userSearchBase.set('ou=people,dc=corp,dc=example')
    component.userSearchFilter.set('(uid={username})')
    component.emailAttribute.set('mail')

    component.save()

    expect(organizationsServiceSpy.setLdapIdentityProvider).toHaveBeenCalledWith('org-1', {
      server_url: 'ldap://dc.corp.example:389',
      bind_dn: 'cn=service,dc=corp,dc=example',
      bind_password: 's3cret!',
      user_search_base: 'ou=people,dc=corp,dc=example',
      user_search_filter: '(uid={username})',
      email_attribute: 'mail',
    })
  })

  it('clears the LDAP configuration', () => {
    setup()
    // clear() is confirm()-gated; jsdom's real confirm() isn't implemented, so stub it.
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    organizationsServiceSpy.clearIdentityProvider.mockReturnValue(of(undefined))

    component.clear()

    expect(organizationsServiceSpy.clearIdentityProvider).toHaveBeenCalledWith('org-1')
  })

  it('shows the OIDC form fields when OIDC is selected as the provider type', () => {
    setup()
    component.selectedProviderType.set('oidc')
    fixture.detectChanges()

    expect(component.selectedProviderType()).toBe('oidc')
  })

  it('reflects an existing OIDC configuration', () => {
    organizationsServiceSpy = {
      get: vi.fn(),
      getIdentityProvider: vi.fn(),
      setLdapIdentityProvider: vi.fn(),
      setOidcIdentityProvider: vi.fn(),
      clearIdentityProvider: vi.fn(),
    }
    organizationsServiceSpy.get.mockReturnValue(
      of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }),
    )
    organizationsServiceSpy.getIdentityProvider.mockReturnValue(
      of({
        type: 'oidc',
        issuer_url: 'https://accounts.example.com',
        client_id: 'hangar',
        client_secret_set: true,
      }),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: vi.fn() } } },
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()

    expect(component.identityProviderConfigured()).toBe(true)
    expect(component.selectedProviderType()).toBe('oidc')
    expect(component.issuerUrl()).toBe('https://accounts.example.com')
    expect(component.clientId()).toBe('hangar')
    expect(component.clientSecretSet()).toBe(true)
  })

  it('saves the OIDC configuration', () => {
    setup()
    organizationsServiceSpy.setOidcIdentityProvider.mockReturnValue(of(undefined))
    component.selectedProviderType.set('oidc')
    component.issuerUrl.set('https://accounts.example.com')
    component.clientId.set('hangar')
    component.clientSecret.set('s3cret!')

    component.save()

    expect(organizationsServiceSpy.setOidcIdentityProvider).toHaveBeenCalledWith('org-1', {
      issuer_url: 'https://accounts.example.com',
      client_id: 'hangar',
      client_secret: 's3cret!',
    })
  })

  it('shows an error and does not optimistically mark the LDAP config as saved when save fails', () => {
    setup()
    organizationsServiceSpy.setLdapIdentityProvider.mockReturnValue(
      throwError(() => new Error('save failed')),
    )
    component.serverUrl.set('ldap://dc.corp.example:389')
    component.bindDn.set('cn=service,dc=corp,dc=example')
    component.bindPassword.set('s3cret!')
    component.userSearchBase.set('ou=people,dc=corp,dc=example')
    component.userSearchFilter.set('(uid={username})')
    component.emailAttribute.set('mail')

    component.save()

    expect(component.errorMessage()).toBe('Échec de la mise à jour de la configuration.')
    expect(component.saving()).toBe(false)
    expect(component.saved()).toBe(false)
    expect(component.identityProviderConfigured()).toBe(false)
    expect(component.bindPasswordSet()).toBe(false)
  })

  it('shows an error and does not optimistically mark the OIDC config as saved when save fails', () => {
    setup()
    organizationsServiceSpy.setOidcIdentityProvider.mockReturnValue(
      throwError(() => new Error('save failed')),
    )
    component.selectedProviderType.set('oidc')
    component.issuerUrl.set('https://accounts.example.com')
    component.clientId.set('hangar')
    component.clientSecret.set('s3cret!')

    component.save()

    expect(component.errorMessage()).toBe('Échec de la mise à jour de la configuration.')
    expect(component.saving()).toBe(false)
    expect(component.saved()).toBe(false)
    expect(component.identityProviderConfigured()).toBe(false)
    expect(component.clientSecretSet()).toBe(false)
  })

  it('shows an error and does not reset the form when clearing the configuration fails', () => {
    organizationsServiceSpy = {
      get: vi.fn(),
      getIdentityProvider: vi.fn(),
      setLdapIdentityProvider: vi.fn(),
      setOidcIdentityProvider: vi.fn(),
      clearIdentityProvider: vi.fn(),
    }
    organizationsServiceSpy.get.mockReturnValue(
      of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }),
    )
    organizationsServiceSpy.getIdentityProvider.mockReturnValue(
      of({
        type: 'ldap',
        server_url: 'ldap://dc.corp.example:389',
        bind_dn: 'cn=service,dc=corp,dc=example',
        bind_password_set: true,
        user_search_base: 'ou=people,dc=corp,dc=example',
        user_search_filter: '(uid={username})',
        email_attribute: 'mail',
      }),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: vi.fn() } } },
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()

    vi.spyOn(window, 'confirm').mockReturnValue(true)
    organizationsServiceSpy.clearIdentityProvider.mockReturnValue(
      throwError(() => new Error('clear failed')),
    )

    component.clear()

    expect(component.errorMessage()).toBe('Échec de la suppression de la configuration.')
    expect(component.clearing()).toBe(false)
    expect(component.identityProviderConfigured()).toBe(true)
    expect(component.serverUrl()).toBe('ldap://dc.corp.example:389')
    expect(component.bindPasswordSet()).toBe(true)
  })

  it('renders the members component with the resolved organization id', () => {
    setup()

    const membersDebugElement = fixture.debugElement.query(By.directive(OrganizationMembers))
    expect(membersDebugElement).not.toBeNull()
    expect(membersDebugElement.componentInstance.organizationId()).toBe('org-1')
  })
})
