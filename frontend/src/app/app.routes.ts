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
        path: 'admin/export',
        loadComponent: () => import('./admin/export/export').then((m) => m.ExportAdmin),
        canActivate: [adminGuard],
        data: { title: 'Export' },
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
          import('./admin/organizations-page/organizations-page').then((m) => m.OrganizationsPage),
        canActivate: [adminGuard],
        data: { title: 'Organisations' },
      },
      {
        path: 'admin/organizations/:id',
        loadComponent: () =>
          import('./admin/organizations-page/organizations-page').then((m) => m.OrganizationsPage),
        canActivate: [organizationAdminGuard],
      },
    ],
  },
]
