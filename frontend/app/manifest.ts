import type { MetadataRoute } from 'next'

// Static export (Next 16): pre-render this metadata route at build time.
export const dynamic = 'force-static'

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
    short_name: 'ThreatOrbit',
    description:
      'Threat intelligence ingestion, ML log anomaly detection, and OpenCTI integration - one unified API.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0A0612',
    theme_color: '#0A0612',
    icons: [
      { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml' },
    ],
  }
}
