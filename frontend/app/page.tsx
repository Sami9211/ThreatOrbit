import Navbar from '@/components/layout/Navbar'
import Footer from '@/components/layout/Footer'
import SmoothScroll from '@/components/effects/SmoothScroll'
import CursorGlow from '@/components/effects/CursorGlow'
import ScrollProgress from '@/components/ui/ScrollProgress'
import Chatbot from '@/components/ui/Chatbot'
import Hero from '@/components/sections/Hero'
import StatsBar from '@/components/sections/StatsBar'
import ScrollStory from '@/components/sections/ScrollStory'
import Features from '@/components/sections/Features'
import ExpandingShowcase from '@/components/sections/ExpandingShowcase'
import ThreatIntelSection from '@/components/sections/ThreatIntelSection'
import LogAnalysisSection from '@/components/sections/LogAnalysisSection'
import OpenCTISection from '@/components/sections/OpenCTISection'
import GlobalThreatMap from '@/components/sections/GlobalThreatMap'
import DashboardPreview from '@/components/sections/DashboardPreview'
import Pricing from '@/components/sections/Pricing'
import About from '@/components/sections/About'
import Contact from '@/components/sections/Contact'
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
        <ScrollStory />
        <Features />
        <ExpandingShowcase />
        <ThreatIntelSection />
        <LogAnalysisSection />
        <OpenCTISection />
        <GlobalThreatMap />
        <DashboardPreview />
        <Pricing />
        <About />
        <Contact />
        <CTA />
      </main>
      <Footer />
      <Chatbot />
    </SmoothScroll>
  )
}
