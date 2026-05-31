import Navbar from '@/components/layout/Navbar'
import Footer from '@/components/layout/Footer'
import SmoothScroll from '@/components/effects/SmoothScroll'
import CursorGlow from '@/components/effects/CursorGlow'
import ScrollProgress from '@/components/ui/ScrollProgress'
import Hero from '@/components/sections/Hero'
import StatsBar from '@/components/sections/StatsBar'
import Features from '@/components/sections/Features'
import ExpandingShowcase from '@/components/sections/ExpandingShowcase'
import HowItWorks from '@/components/sections/HowItWorks'
import ThreatIntelSection from '@/components/sections/ThreatIntelSection'
import LogAnalysisSection from '@/components/sections/LogAnalysisSection'
import OpenCTISection from '@/components/sections/OpenCTISection'
import DashboardPreview from '@/components/sections/DashboardPreview'
import CTA from '@/components/sections/CTA'

export default function Home() {
  return (
    <SmoothScroll>
      <ScrollProgress />
      <CursorGlow />
      <Navbar />
      <main>
        <Hero />
        <StatsBar />
        <Features />
        <ExpandingShowcase />
        <HowItWorks />
        <ThreatIntelSection />
        <LogAnalysisSection />
        <OpenCTISection />
        <DashboardPreview />
        <CTA />
      </main>
      <Footer />
    </SmoothScroll>
  )
}
