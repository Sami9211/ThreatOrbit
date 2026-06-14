import type { MetadataRoute } from 'next'

// Static export (Next 16): pre-render this metadata route at build time.
export const dynamic = 'force-static'

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
