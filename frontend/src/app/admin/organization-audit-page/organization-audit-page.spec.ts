import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationAuditPage } from './organization-audit-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { AuditLog } from '../audit-log/audit-log'
import { OrganizationsService } from '../application/organizations.service'
import { AuditService } from '../application/audit.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationAuditPage', () => {
  it('renders the context banner and the audit log', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationAuditPage],
      providers: [
        {
          provide: OrganizationsService,
          useValue: { get: () => of({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' }) },
        },
        { provide: MeService, useValue: { isSuperAdmin: () => false } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { paramMap: convertToParamMap({ id: 'org-1' }) } },
        },
        { provide: AuditService, useValue: { query: () => of([]), blockedAccounts: () => of([]) } },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationAuditPage)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(AuditLog))).not.toBeNull()
  })
})
