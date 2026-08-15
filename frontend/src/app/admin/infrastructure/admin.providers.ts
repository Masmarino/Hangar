import { Provider } from '@angular/core'
import { ADMIN_API_TOKEN_PORT } from '../application/admin-api-token.port'
import { HttpAdminApiTokenAdapter } from './http-admin-api-token.adapter'
import { AUDIT_PORT } from '../application/audit.port'
import { HttpAuditAdapter } from './http-audit.adapter'
import { BRANDING_PORT } from '../application/branding.port'
import { HttpBrandingAdapter } from './http-branding.adapter'
import { EXPORT_PORT } from '../application/export.port'
import { HttpExportAdapter } from './http-export.adapter'
import { METRICS_PORT } from '../application/metrics.port'
import { HttpMetricsAdapter } from './http-metrics.adapter'
import { SMTP_SETTINGS_PORT } from '../application/smtp-settings.port'
import { HttpSmtpSettingsAdapter } from './http-smtp-settings.adapter'
import { SYSTEM_SETTINGS_PORT } from '../application/system-settings.port'
import { HttpSystemSettingsAdapter } from './http-system-settings.adapter'

export const adminProviders: Provider[] = [
  { provide: ADMIN_API_TOKEN_PORT, useClass: HttpAdminApiTokenAdapter },
  { provide: AUDIT_PORT, useClass: HttpAuditAdapter },
  { provide: BRANDING_PORT, useClass: HttpBrandingAdapter },
  { provide: EXPORT_PORT, useClass: HttpExportAdapter },
  { provide: METRICS_PORT, useClass: HttpMetricsAdapter },
  { provide: SMTP_SETTINGS_PORT, useClass: HttpSmtpSettingsAdapter },
  { provide: SYSTEM_SETTINGS_PORT, useClass: HttpSystemSettingsAdapter },
]
