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
        bg: '#030711',
        surface: '#080d1a',
        'surface-2': '#0d1424',
        'surface-3': '#111827',
        cyan: {
          DEFAULT: '#00D4FF',
          50: 'rgba(0,212,255,0.05)',
          100: 'rgba(0,212,255,0.1)',
          200: 'rgba(0,212,255,0.2)',
          400: 'rgba(0,212,255,0.4)',
          glow: '0 0 30px rgba(0,212,255,0.4), 0 0 80px rgba(0,212,255,0.15)',
        },
        violet: {
          DEFAULT: '#7B2FBE',
          50: 'rgba(123,47,190,0.05)',
          100: 'rgba(123,47,190,0.1)',
          glow: '0 0 30px rgba(123,47,190,0.4)',
        },
        threat: '#FF3366',
        safe: '#00FF88',
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
        'border-flow': 'borderFlow 4s linear infinite',
        'float': 'float 7s ease-in-out infinite',
        'float-delayed': 'float 7s ease-in-out 3.5s infinite',
        'scan': 'scan 4s ease-in-out infinite',
        'ticker': 'ticker 20s linear infinite',
        'gradient-x': 'gradientX 5s ease infinite',
        'spin-slow': 'spin 25s linear infinite',
        'ping-slow': 'ping 3s cubic-bezier(0,0,0.2,1) infinite',
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
          '0%, 100%': { opacity: '0.6', filter: 'blur(20px)' },
          '50%': { opacity: '1', filter: 'blur(10px)' },
        },
        borderFlow: {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px) rotate(0deg)' },
          '33%': { transform: 'translateY(-12px) rotate(1deg)' },
          '66%': { transform: 'translateY(-6px) rotate(-1deg)' },
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
      },
      backgroundImage: {
        'grid-dim': "url(\"data:image/svg+xml,%3Csvg width='50' height='50' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M50 0 L50 50 M0 50 L50 50' stroke='%23ffffff' stroke-width='0.4' stroke-opacity='0.04' fill='none'/%3E%3C/svg%3E\")",
        'radial-cyan': 'radial-gradient(ellipse 60% 40% at 50% 0%, rgba(0,212,255,0.12), transparent)',
        'radial-violet': 'radial-gradient(ellipse 60% 40% at 50% 100%, rgba(123,47,190,0.1), transparent)',
      },
      boxShadow: {
        'cyan-sm': '0 0 15px rgba(0,212,255,0.25)',
        'cyan-md': '0 0 30px rgba(0,212,255,0.35), 0 0 60px rgba(0,212,255,0.1)',
        'cyan-lg': '0 0 50px rgba(0,212,255,0.4), 0 0 100px rgba(0,212,255,0.15)',
        'violet-sm': '0 0 15px rgba(123,47,190,0.3)',
        'violet-md': '0 0 30px rgba(123,47,190,0.4)',
        'card': '0 0 0 1px rgba(255,255,255,0.06), 0 4px 24px rgba(0,0,0,0.4)',
        'card-hover': '0 0 0 1px rgba(0,212,255,0.25), 0 8px 40px rgba(0,0,0,0.5), 0 0 30px rgba(0,212,255,0.08)',
      },
    },
  },
  plugins: [],
}

export default config
