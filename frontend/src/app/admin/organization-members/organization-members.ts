import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { Button, Checkbox, GbtInput } from '@masmarino/gabarit'
import { OrganizationMembersService } from '../application/organization-members.service'
import { OrganizationMember } from '../domain/organization-member.entity'

@Component({
  selector: 'app-organization-members',
  standalone: true,
  imports: [Button, GbtInput, Checkbox, FormsModule],
  templateUrl: './organization-members.html',
  styleUrl: './organization-members.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationMembers implements OnInit {
  private readonly organizationMembersService = inject(OrganizationMembersService)

  readonly organizationId = input.required<string>()

  readonly members = signal<OrganizationMember[]>([])
  readonly loading = signal(true)
  readonly errorMessage = signal<string | null>(null)

  readonly addingMember = signal(false)
  readonly newUsername = signal('')
  readonly newEmail = signal('')
  readonly newIsOrganizationAdmin = signal(false)
  readonly inviting = signal(false)

  ngOnInit(): void {
    this.reload()
  }

  private reload(): void {
    this.organizationMembersService.list(this.organizationId()).subscribe({
      next: (members) => {
        this.members.set(members)
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.errorMessage.set('Échec du chargement des membres.')
      },
    })
  }

  startAdding(): void {
    this.addingMember.set(true)
    this.newUsername.set('')
    this.newEmail.set('')
    this.newIsOrganizationAdmin.set(false)
    this.errorMessage.set(null)
  }

  cancelAdding(): void {
    this.addingMember.set(false)
  }

  invite(): void {
    if (this.newUsername().trim() === '' || this.newEmail().trim() === '' || this.inviting()) {
      return
    }
    this.inviting.set(true)
    this.errorMessage.set(null)
    this.organizationMembersService
      .invite(this.organizationId(), this.newUsername(), this.newEmail(), this.newIsOrganizationAdmin())
      .subscribe({
        next: () => {
          this.inviting.set(false)
          this.addingMember.set(false)
          this.reload()
        },
        error: () => {
          this.inviting.set(false)
          this.errorMessage.set("Échec de l'invitation.")
        },
      })
  }

  toggleOrganizationAdmin(member: OrganizationMember): void {
    const promoting = !member.is_organization_admin
    const verb = promoting ? 'promouvoir' : 'rétrograder'
    if (!confirm(`Voulez-vous ${verb} ${member.username} ${promoting ? 'en administrateur' : "de son rôle d'administrateur"} de l'organisation ?`)) {
      return
    }
    this.errorMessage.set(null)
    this.organizationMembersService.setOrganizationAdmin(this.organizationId(), member.id, promoting).subscribe({
      next: () => this.reload(),
      error: () => this.errorMessage.set("Échec de la mise à jour du statut d'administrateur."),
    })
  }
}
