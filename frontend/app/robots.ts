import type { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      // The operator dashboard is a private, authenticated area.
      disallow: ['/dashboard/', '/login/', '/signup/'],
    },
    sitemap: 'https://threatorbit.space/sitemap.xml',
  }
}
