import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HealthStatusPage } from './health-status'
import { adminProviders } from '../infrastructure/admin.providers'

describe('HealthStatusPage', () => {
  function render() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(HealthStatusPage)
    const httpMock = TestBed.inject(HttpTestingController)
    fixture.detectChanges()
    httpMock.expectOne('/api/admin/health').flush({
      database: {
        status: 'up',
        detail: null,
        response_time_ms: 4,
        active_connections: 3,
        max_connections: 10,
        server_version: '18.0',
      },
      storage: {
        status: 'down',
        detail: 'disk full',
        used_bytes: 900,
        free_bytes: 100,
        total_bytes: 1000,
      },
      uptime_seconds: 3725,
    })
    fixture.detectChanges()
    return fixture
  }

  it('shows database connection count, response time and version', () => {
    const fixture = render()
    const text = fixture.nativeElement.textContent as string

    expect(text).toContain('4 ms')
    expect(text).toContain('3 / 10')
    expect(text).toContain('18.0')
  })

  it('shows storage status detail and space usage', () => {
    const fixture = render()
    const text = fixture.nativeElement.textContent as string

    expect(text).toContain('down')
    expect(text).toContain('disk full')
    expect(text).toContain('900')
    expect(text).toContain('1000')
    expect(text).toContain('100')
  })

  it('shows server uptime', () => {
    const fixture = render()
    const text = fixture.nativeElement.textContent as string

    expect(text).toContain('1 h')
    expect(text).toContain('2 min')
  })

  it('renders the connections and storage gauges at their correct ratio', () => {
    const fixture = render()

    const gauges: HTMLElement[] = Array.from(
      fixture.nativeElement.querySelectorAll('gbt-gauge-bar .gbt-gauge-bar__fill'),
    )
    // Connections: 3/10 = 30%; storage used: 900/1000 = 90% (critical, past the 90% threshold).
    expect(gauges[0].style.width).toBe('30%')
    expect(gauges[1].style.width).toBe('90%')
    expect(gauges[1].getAttribute('data-tier')).toBe('critical')
  })

  it('formats uptime with days, hours and minutes as needed', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
    })
    const fixture = TestBed.createComponent(HealthStatusPage)
    const component = fixture.componentInstance

    expect(component.formatUptime(59)).toBe('0 min')
    expect(component.formatUptime(3725)).toBe('1 h 2 min')
    expect(component.formatUptime(90000)).toBe('1 j 1 h 0 min')
  })
})
