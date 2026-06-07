import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // All theme tokens are driven by CSS variables (see app/globals.css)
        // so the dashboard can swap colour schemes at runtime via [data-theme].
        // The channel format `rgb(var(--x) / <alpha-value>)` keeps Tailwind's
        // /opacity modifiers working (e.g. bg-magenta/20).
        bg: 'rgb(var(--bg) / <alpha-value>)',
        surface: 'rgb(var(--surface) / <alpha-value>)',
        'surface-2': 'rgb(var(--surface-2) / <alpha-value>)',
        'surface-3': 'rgb(var(--surface-3) / <alpha-value>)',
        // Signature plasma accents
        magenta: {
          DEFAULT: 'rgb(var(--magenta) / <alpha-value>)',
          50: 'rgb(var(--magenta) / 0.05)',
          100: 'rgb(var(--magenta) / 0.1)',
          200: 'rgb(var(--magenta) / 0.2)',
          400: 'rgb(var(--magenta) / 0.4)',
        },
        violet: {
          DEFAULT: 'rgb(var(--violet) / <alpha-value>)',
          50: 'rgb(var(--violet) / 0.05)',
          100: 'rgb(var(--violet) / 0.1)',
          200: 'rgb(var(--violet) / 0.2)',
          400: 'rgb(var(--violet) / 0.4)',
        },
        amber: {
          DEFAULT: 'rgb(var(--amber) / <alpha-value>)',
          100: 'rgb(var(--amber) / 0.1)',
          200: 'rgb(var(--amber) / 0.2)',
        },
        // Minor cool supporting tone (keeps the blue family whispering)
        teal: {
          DEFAULT: 'rgb(var(--teal) / <alpha-value>)',
          100: 'rgb(var(--teal) / 0.1)',
        },
        threat: 'rgb(var(--threat) / <alpha-value>)',
        safe: 'rgb(var(--safe) / <alpha-value>)',
        // Warm-tinted neutral ink for cohesion with the violet base
        ink: {
          100: 'rgb(var(--ink-100) / <alpha-value>)',
          200: 'rgb(var(--ink-200) / <alpha-value>)',
          300: 'rgb(var(--ink-300) / <alpha-value>)',
          400: 'rgb(var(--ink-400) / <alpha-value>)',
          500: 'rgb(var(--ink-500) / <alpha-value>)',
          600: 'rgb(var(--ink-600) / <alpha-value>)',
          700: 'rgb(var(--ink-700) / <alpha-value>)',
          800: 'rgb(var(--ink-800) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        display: ['var(--font-space-grotesk)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-jetbrains-mono)', 'monospace'],
      },
      animation: {
        'fade-up': 'fadeUp 0.7s ease-out forwards',
        'fade-in': 'fadeIn 0.8s ease-out forwards',
        'glow-pulse': 'glowPulse 3s ease-in-out infinite',
        'border-flow': 'borderFlow 5s linear infinite',
        'float': 'float 7s ease-in-out infinite',
        'float-delayed': 'float 7s ease-in-out 3.5s infinite',
        'scan': 'scan 5s ease-in-out infinite',
        'ticker': 'ticker 24s linear infinite',
        'gradient-x': 'gradientX 6s ease infinite',
        'spin-slow': 'spin 28s linear infinite',
        'spin-reverse': 'spinReverse 22s linear infinite',
        'ping-slow': 'ping 3s cubic-bezier(0,0,0.2,1) infinite',
        'drift': 'drift 18s ease-in-out infinite',
      },
      keyframes: {
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(28px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        glowPulse: {
          '0%, 100%': { opacity: '0.5', filter: 'blur(22px)' },
          '50%': { opacity: '1', filter: 'blur(12px)' },
        },
        borderFlow: {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px) rotate(0deg)' },
          '33%': { transform: 'translateY(-14px) rotate(1deg)' },
          '66%': { transform: 'translateY(-7px) rotate(-1deg)' },
        },
        scan: {
          '0%': { top: '-5%', opacity: '0' },
          '10%': { opacity: '1' },
          '90%': { opacity: '1' },
          '100%': { top: '105%', opacity: '0' },
        },
        ticker: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        gradientX: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        spinReverse: {
          '0%': { transform: 'rotate(360deg)' },
          '100%': { transform: 'rotate(0deg)' },
        },
        drift: {
          '0%, 100%': { transform: 'translate(0,0) scale(1)' },
          '50%': { transform: 'translate(4%,-3%) scale(1.08)' },
        },
      },
      backgroundImage: {
        'grid-dim': "url(\"data:image/svg+xml,%3Csvg width='52' height='52' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M52 0 L52 52 M0 52 L52 52' stroke='%23ffffff' stroke-width='0.4' stroke-opacity='0.04' fill='none'/%3E%3C/svg%3E\")",
        'radial-magenta': 'radial-gradient(ellipse 60% 40% at 50% 0%, rgb(var(--magenta) / 0.14), transparent)',
        'radial-violet': 'radial-gradient(ellipse 60% 50% at 50% 100%, rgb(var(--violet) / 0.12), transparent)',
        'plasma': 'linear-gradient(135deg, rgb(var(--magenta)) 0%, rgb(var(--violet)) 55%, rgb(var(--amber)) 100%)',
      },
      boxShadow: {
        'magenta-sm': '0 0 16px rgba(255,46,151,0.3)',
        'magenta-md': '0 0 32px rgba(255,46,151,0.4), 0 0 64px rgba(255,46,151,0.12)',
        'magenta-lg': '0 0 50px rgba(255,46,151,0.45), 0 0 110px rgba(255,46,151,0.18)',
        'violet-sm': '0 0 16px rgba(122,60,255,0.35)',
        'violet-md': '0 0 32px rgba(122,60,255,0.45)',
        'card': '0 0 0 1px rgba(255,255,255,0.06), 0 4px 24px rgba(0,0,0,0.5)',
        'card-hover': '0 0 0 1px rgba(255,46,151,0.25), 0 12px 48px rgba(0,0,0,0.6), 0 0 36px rgba(122,60,255,0.12)',
      },
    },
  },
  plugins: [],
}

export default config
