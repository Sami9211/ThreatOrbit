import Link from 'next/link'
import { ArrowLeft, Home } from 'lucide-react'
import Logo from '@/components/ui/Logo'

export default function NotFound() {
  return (
    <main className="relative min-h-screen flex flex-col items-center justify-center bg-bg overflow-hidden px-6">
      <div className="absolute inset-0 plasma-mesh opacity-40 pointer-events-none" />
      <div className="absolute inset-0 bg-grid-dim opacity-20 pointer-events-none" />

      <div className="relative text-center">
        <div className="flex justify-center mb-8">
          <Logo size={72} />
        </div>

        <h1 className="font-display text-7xl md:text-8xl font-bold mb-4">
          <span className="text-gradient-plasma">404</span>
        </h1>
        <h2 className="font-display text-2xl md:text-3xl font-bold text-white mb-3">
          Signal lost.
        </h2>
        <p className="text-ink-400 max-w-md mx-auto mb-10">
          This indicator never made it into the library. The page you&apos;re looking for
          has drifted out of orbit or never existed.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4">
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-plasma text-white font-semibold text-sm hover:shadow-magenta-md transition-shadow"
          >
            <Home className="w-4 h-4" />
            Back to home
          </Link>
          <Link
            href="/docs"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-white/25 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Read the docs
          </Link>
        </div>
      </div>
    </main>
  )
}
