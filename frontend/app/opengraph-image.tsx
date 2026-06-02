import { ImageResponse } from 'next/og'

export const alt = 'ThreatOrbit · Enterprise Threat Intelligence Platform'
export const size = { width: 1200, height: 630 }
export const contentType = 'image/png'

export default function OgImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '80px',
          background:
            'radial-gradient(circle at 20% 20%, #2A0A3A 0%, #0A0612 55%)',
          color: '#F5F0FA',
          fontFamily: 'sans-serif',
        }}
      >
        {/* Brand row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 44 }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 16,
              background: 'linear-gradient(135deg, #FF2E97, #7A3CFF)',
              display: 'flex',
            }}
          />
          <div style={{ display: 'flex', fontSize: 38, fontWeight: 700, letterSpacing: -1 }}>
            <span style={{ color: '#fff' }}>Threat</span>
            <span style={{ color: '#FF2E97' }}>Orbit</span>
          </div>
        </div>

        {/* Headline */}
        <div
          style={{
            fontSize: 92,
            fontWeight: 800,
            lineHeight: 1.05,
            letterSpacing: -3,
            display: 'flex',
            flexWrap: 'wrap',
          }}
        >
          <span style={{ color: '#fff' }}>Detect.&nbsp;</span>
          <span style={{ color: '#FF2E97' }}>Analyze.&nbsp;</span>
          <span style={{ color: '#fff' }}>Neutralize.</span>
        </div>

        {/* Subtitle */}
        <div style={{ fontSize: 32, color: '#B4A8C8', marginTop: 36, maxWidth: 900 }}>
          Threat intelligence ingestion, ML log anomaly detection, and OpenCTI
          integration — one unified API.
        </div>

        {/* Bottom accent line */}
        <div
          style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            width: '100%',
            height: 12,
            background: 'linear-gradient(90deg, #FF2E97, #7A3CFF, #FFB23E)',
          }}
        />
      </div>
    ),
    { ...size },
  )
}
