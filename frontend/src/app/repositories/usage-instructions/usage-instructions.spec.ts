import { DOCUMENT } from '@angular/common'
import { TestBed } from '@angular/core/testing'
import { provideRouter } from '@angular/router'
import { UsageInstructions } from './usage-instructions'
import { RepositorySummary } from '../domain/repository.entity'

const FAKE_LOCATION = { origin: 'http://hangar.test:8080', host: 'hangar.test:8080' }
const FAKE_DOCUMENT = {
  location: FAKE_LOCATION,
  createElement: (tag: string) => document.createElement(tag),
  createTextNode: (text: string) => document.createTextNode(text),
  createComment: (text: string) => document.createComment(text),
  querySelector: (selector: string) => document.querySelector(selector),
  body: document.body,
}

function repo(overrides: Partial<RepositorySummary>): RepositorySummary {
  return {
    id: 'repo-1',
    name: 'my-repo',
    format: 'npm',
    repo_type: 'hosted',
    remote_url: null,
    remote_credentials_set: false,
    group_members: [],
    quota_bytes: null,
    retention_keep_last_n: null,
    my_role: 'admin',
    ...overrides,
  }
}

function render(repository: RepositorySummary) {
  TestBed.configureTestingModule({
    providers: [provideRouter([]), { provide: DOCUMENT, useValue: FAKE_DOCUMENT }],
  })
  const fixture = TestBed.createComponent(UsageInstructions)
  fixture.componentRef.setInput('repository', repository)
  fixture.detectChanges()
  return fixture
}

describe('UsageInstructions', () => {
  it('shows docker login, tag, push and pull for a hosted docker repository', () => {
    const text = render(repo({ name: 'my-images', format: 'docker', repo_type: 'hosted' }))
      .nativeElement.textContent

    expect(text).toContain('docker login hangar.test:8080')
    expect(text).toContain('--password-stdin')
    expect(text).toContain('docker tag')
    expect(text).toContain('docker push hangar.test:8080/my-images/')
    expect(text).toContain('docker pull hangar.test:8080/my-images/')
  })

  it('shows docker login and pull only for a proxy docker repository, never push', () => {
    const text = render(repo({ name: 'docker-hub-proxy', format: 'docker', repo_type: 'proxy' }))
      .nativeElement.textContent

    expect(text).toContain('docker login hangar.test:8080')
    expect(text).toContain('docker pull hangar.test:8080/docker-hub-proxy/')
    expect(text).not.toContain('docker push')
    expect(text).not.toContain('docker tag')
  })

  it('shows the .npmrc block and publish/install for a hosted npm repository', () => {
    const text = render(repo({ name: 'my-packages', format: 'npm', repo_type: 'hosted' }))
      .nativeElement.textContent

    expect(text).toContain('registry=http://hangar.test:8080/npm/my-packages/')
    expect(text).toContain('//hangar.test:8080/npm/my-packages/:_authToken=<votre-token>')
    expect(text).toContain('npm publish')
    expect(text).toContain('npm install')
  })

  it('shows the .npmrc block and install only for a group npm repository, never publish', () => {
    const text = render(repo({ name: 'aggregated', format: 'npm', repo_type: 'group' }))
      .nativeElement.textContent

    expect(text).toContain('registry=http://hangar.test:8080/npm/aggregated/')
    expect(text).toContain('npm install')
    expect(text).not.toContain('npm publish')
  })

  it('links to the API tokens page and never renders a real token', () => {
    const fixture = render(repo({}))

    const link: HTMLAnchorElement = fixture.nativeElement.querySelector('a[href="/account"]')
    expect(link).toBeTruthy()
    expect(fixture.nativeElement.textContent).toContain('<votre-token>')
  })
})
