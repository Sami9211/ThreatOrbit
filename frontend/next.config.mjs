/** @type {import('next').NextConfig} */

// Security headers. In the previous static+nginx/Vercel setup these were set by
// nginx.conf (self-host) and vercel.json (Vercel). A Node `next start` server
// reads neither, so they are applied here via headers() - which SSR honours
// (static export silently ignored it) - keeping every deploy target consistent.
const SECURITY_HEADERS = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http: https: ws: wss:; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  },
]

const nextConfig = {
  // Node SSR deployment (was `output: 'export'` / static). Plain SSR: the build
  // emits `.next`, served by `next start` consistently everywhere (Docker,
  // linux-start.sh, e2e). No `output` field = the default Next server.
  trailingSlash: true,
  transpilePackages: ['three'],
  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }]
  },
}

export default nextConfig
