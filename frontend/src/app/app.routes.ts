import { Routes } from '@angular/router'
import { authGuard } from './auth/auth.guard'
import { adminGuard } from './auth/admin.guard'
import { usersGuard } from './auth/users.guard'
import { organizationAdminGuard } from './auth/organization-admin.guard'

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./auth/login-page/login-page').then((m) => m.LoginPage),
  },
  {
    path: 'activate',
    loadComponent: () => import('./auth/activate-page/activate-page').then((m) => m.ActivatePage),
  },
  {
    path: 'register',
    loadComponent: () => import('./auth/register-page/register-page').then((m) => m.RegisterPage),
  },
  {
    path: '',
    loadComponent: () => import('./shell/app-shell').then((m) => m.AppShell),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'repositories', pathMatch: 'full' },
      {
        path: 'users',
        loadComponent: () => import('./users/users-list/users-list').then((m) => m.UsersList),
        canActivate: [usersGuard],
        data: { title: 'Utilisateurs' },
      },
      {
        path: 'users/:id',
        loadComponent: () => import('./users/user-detail/user-detail').then((m) => m.UserDetail),
        canActivate: [usersGuard],
      },
      {
        path: 'account',
        loadComponent: () =>
          import('./account/account-page/account-page').then((m) => m.AccountPage),
        data: { title: 'Mon compte' },
      },
      {
        path: 'repositories',
        loadComponent: () =>
          import('./repositories/repositories-list/repositories-list').then(
            (m) => m.RepositoriesList,
          ),
        data: { title: 'Dépôts' },
      },
      {
        path: 'repositories/:id',
        loadComponent: () =>
          import('./repositories/repository-detail/repository-detail').then(
            (m) => m.RepositoryDetail,
          ),
      },
      {
        path: 'repositories/:id/packages/:format/:name',
        loadComponent: () =>
          import('./repositories/package-detail-page/package-detail-page').then(
            (m) => m.PackageDetailPage,
          ),
      },
      {
        path: 'admin',
        loadComponent: () =>
          import('./admin/admin-dashboard/admin-dashboard').then((m) => m.AdminDashboard),
        canActivate: [adminGuard],
        data: { title: 'Administration' },
      },
      {
        path: 'admin/audit',
        loadComponent: () => import('./admin/audit-log/audit-log').then((m) => m.AuditLog),
        canActivate: [adminGuard],
        data: { title: 'Historique' },
      },
      {
        path: 'admin/security',
        loadComponent: () => import('./admin/security-log/security-log').then((m) => m.SecurityLog),
        canActivate: [adminGuard],
        data: { title: 'Journal de sécurité' },
      },
      {
        path: 'admin/tokens',
        loadComponent: () => import('./admin/api-tokens/api-tokens').then((m) => m.ApiTokensAdmin),
        canActivate: [adminGuard],
        data: { title: 'Jetons API' },
      },
      {
        path: 'admin/settings',
        loadComponent: () =>
          import('./admin/system-settings/system-settings').then((m) => m.SystemSettingsAdmin),
        canActivate: [adminGuard],
        data: { title: 'Paramètres système' },
      },
      {
        path: 'admin/smtp',
        loadComponent: () =>
          import('./admin/smtp-settings/smtp-settings').then((m) => m.SmtpSettingsAdmin),
        canActivate: [adminGuard],
        data: { title: 'Serveur mail' },
      },
      {
        path: 'admin/branding',
        loadComponent: () =>
          import('./admin/branding-settings/branding-settings').then(
            (m) => m.BrandingSettingsAdmin,
          ),
        canActivate: [adminGuard],
        data: { title: 'Marque' },
      },
      {
        path: 'admin/export',
        loadComponent: () => import('./admin/export/export').then((m) => m.ExportAdmin),
        canActivate: [adminGuard],
        data: { title: 'Export' },
      },
      {
        path: 'admin/metrics',
        loadComponent: () =>
          import('./admin/usage-metrics/usage-metrics').then((m) => m.UsageMetrics),
        canActivate: [adminGuard],
        data: { title: "Métriques d'usage" },
      },
      {
        path: 'admin/health',
        loadComponent: () =>
          import('./admin/health-status/health-status').then((m) => m.HealthStatusPage),
        canActivate: [adminGuard],
        data: { title: 'Santé système' },
      },
      {
        path: 'admin/organizations',
        loadComponent: () =>
          import('./admin/organizations-list/organizations-list').then((m) => m.OrganizationsList),
        canActivate: [adminGuard],
        data: { title: 'Organisations' },
      },
      {
        path: 'admin/organizations/:id',
        loadComponent: () =>
          import('./admin/organization-detail/organization-detail').then(
            (m) => m.OrganizationDetail,
          ),
        canActivate: [organizationAdminGuard],
      },
      {
        path: 'admin/organizations/:id/branding',
        loadComponent: () =>
          import('./admin/organization-branding-page/organization-branding-page').then(
            (m) => m.OrganizationBrandingPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Marque' },
      },
      {
        path: 'admin/organizations/:id/tokens',
        loadComponent: () =>
          import('./admin/organization-tokens-page/organization-tokens-page').then(
            (m) => m.OrganizationTokensPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Jetons API' },
      },
      {
        path: 'admin/organizations/:id/audit',
        loadComponent: () =>
          import('./admin/organization-audit-page/organization-audit-page').then(
            (m) => m.OrganizationAuditPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Historique' },
      },
      {
        path: 'admin/organizations/:id/security',
        loadComponent: () =>
          import('./admin/organization-security-page/organization-security-page').then(
            (m) => m.OrganizationSecurityPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Journal de sécurité' },
      },
      {
        path: 'admin/organizations/:id/metrics',
        loadComponent: () =>
          import('./admin/organization-metrics-page/organization-metrics-page').then(
            (m) => m.OrganizationMetricsPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: "Métriques d'usage" },
      },
      {
        path: 'admin/organizations/:id/settings',
        loadComponent: () =>
          import('./admin/organization-settings-page/organization-settings-page').then(
            (m) => m.OrganizationSettingsPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Paramètres système' },
      },
      {
        path: 'admin/organizations/:id/smtp',
        loadComponent: () =>
          import('./admin/organization-smtp-page/organization-smtp-page').then(
            (m) => m.OrganizationSmtpPage,
          ),
        canActivate: [organizationAdminGuard],
        data: { title: 'Serveur mail' },
      },
    ],
  },
]
