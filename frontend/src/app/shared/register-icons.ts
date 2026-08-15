import { inject, provideAppInitializer } from '@angular/core'
import { IconRegistry } from '@masmarino/gabarit'

/** Icons specific to Hangar — Gabarit's own components provide their own set already. */
const HANGAR_ICONS: Record<string, string> = {
  package: `<path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z" />
<path d="M12 22V12" />
<polyline points="3.29 7 12 12 20.71 7" />
<path d="m7.5 4.27 9 5.15" />`,
  users: `<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
<path d="M16 3.128a4 4 0 0 1 0 7.744" />
<path d="M22 21v-2a4 4 0 0 0-3-3.87" />
<circle cx="9" cy="7" r="4" />`,
  history: `<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
<path d="M3 3v5h5" />
<path d="M12 7v5l4 2" />`,
  'bar-chart': `<path d="M3 3v16a2 2 0 0 0 2 2h16" />
<path d="M18 17V9" />
<path d="M13 17V5" />
<path d="M8 17v-3" />`,
  shield: `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />`,
  key: `<path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4" />
<path d="m21 2-9.6 9.6" />
<circle cx="7.5" cy="15.5" r="5.5" />`,
  user: `<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
<circle cx="12" cy="7" r="4" />`,
  'layout-dashboard': `<rect width="7" height="9" x="3" y="3" rx="1" />
<rect width="7" height="5" x="14" y="3" rx="1" />
<rect width="7" height="9" x="14" y="12" rx="1" />
<rect width="7" height="5" x="3" y="16" rx="1" />`,
  activity: `<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />`,
  'log-out': `<path d="m16 17 5-5-5-5" />
<path d="M21 12H9" />
<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />`,
  settings: `<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
<circle cx="12" cy="12" r="3" />`,
  download: `<path d="M12 15V3" />
<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
<path d="m7 10 5 5 5-5" />`,
  mail: `<path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7" />
<rect x="2" y="4" width="20" height="16" rx="2" />`,
  image: `<rect width="18" height="18" x="3" y="3" rx="2" ry="2" />
<circle cx="9" cy="9" r="2" />
<path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21" />`,
  database: `<ellipse cx="12" cy="5" rx="9" ry="3" />
<path d="M3 5V19A9 3 0 0 0 21 19V5" />
<path d="M3 12A9 3 0 0 0 21 12" />`,
  'hard-drive': `<path d="M10 16h.01" />
<path d="M2.212 11.577a2 2 0 0 0-.212.896V18a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-5.527a2 2 0 0 0-.212-.896L18.55 5.11A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
<path d="M21.946 12.013H2.054" />
<path d="M6 16h.01" />`,
  server: `<rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
<rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
<line x1="6" x2="6.01" y1="6" y2="6" />
<line x1="6" x2="6.01" y1="18" y2="18" />`,
  lock: `<rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
<path d="M7 11V7a5 5 0 0 1 10 0v4" />`,
  upload: `<path d="M12 3v12" />
<path d="m17 8-5-5-5 5" />
<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />`,
  'trending-up': `<path d="M16 7h6v6" />
<path d="m22 7-8.5 8.5-5-5L2 17" />`,
  send: `<path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z" />
<path d="m21.854 2.147-10.94 10.939" />`,
  'triangle-alert': `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
<path d="M12 9v4" />
<path d="M12 17h.01" />`,
  terminal: `<path d="M12 19h8" />
<path d="m4 17 6-6-6-6" />`,
}

export const provideHangarIcons = () =>
  provideAppInitializer(() => {
    inject(IconRegistry).registerAll(HANGAR_ICONS)
  })
