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
        // Plasma Noir base: obsidian with a warm violet undertone
        bg: '#0A0612',
        surface: '#100A1C',
        'surface-2': '#160E28',
        'surface-3': '#1E1336',
        // Signature plasma accents
        magenta: {
          DEFAULT: '#FF2E97',
          50: 'rgba(255,46,151,0.05)',
          100: 'rgba(255,46,151,0.1)',
          200: 'rgba(255,46,151,0.2)',
          400: 'rgba(255,46,151,0.4)',
        },
        violet: {
          DEFAULT: '#7A3CFF',
          50: 'rgba(122,60,255,0.05)',
          100: 'rgba(122,60,255,0.1)',
          200: 'rgba(122,60,255,0.2)',
          400: 'rgba(122,60,255,0.4)',
        },
        amber: {
          DEFAULT: '#FFB23E',
          100: 'rgba(255,178,62,0.1)',
          200: 'rgba(255,178,62,0.2)',
        },
        // Minor cool supporting tone (keeps the blue family whispering)
        teal: {
          DEFAULT: '#2DD4BF',
          100: 'rgba(45,212,191,0.1)',
        },
        threat: '#FF4D6D',
        safe: '#34F5C5',
        // Warm-tinted neutral ink for cohesion with the violet base
        ink: {
          100: '#F5F0FA',
          200: '#D9D0E6',
          300: '#B4A8C8',
          400: '#8A7DA3',
          500: '#665B7D',
          600: '#473F5C',
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
        'radial-magenta': 'radial-gradient(ellipse 60% 40% at 50% 0%, rgba(255,46,151,0.14), transparent)',
        'radial-violet': 'radial-gradient(ellipse 60% 50% at 50% 100%, rgba(122,60,255,0.12), transparent)',
        'plasma': 'linear-gradient(135deg, #FF2E97 0%, #7A3CFF 55%, #FFB23E 100%)',
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
