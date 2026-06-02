import type { MetadataRoute } from 'next'

const BASE = 'https://threatorbit.io'

const ROUTES = [
  '',
  '/docs',
  '/docs/quick-start',
  '/docs/authentication',
  '/docs/rest-api',
  '/docs/docker-deploy',
  '/docs/changelog',
  '/products/super-soc',
  '/products/cti-library',
  '/products/siem-soar',
  '/platform/threat-intelligence',
  '/platform/log-analysis',
  '/platform/opencti',
  '/security',
  '/privacy',
  '/terms',
]

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date()
  return ROUTES.map((path) => ({
    url: `${BASE}${path}`,
    lastModified: now,
    changeFrequency: path === '' ? 'weekly' : 'monthly',
    priority: path === '' ? 1 : 0.7,
  }))
}
