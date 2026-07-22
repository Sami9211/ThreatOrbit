import Navbar from '@/components/layout/Navbar'
import LandingSidebar from '@/components/layout/LandingSidebar'
import Footer from '@/components/layout/Footer'
import CursorGlow from '@/components/effects/CursorGlow'
import CursorParticles from '@/components/effects/CursorParticles'
import Preloader from '@/components/effects/Preloader'
import ScrollProgress from '@/components/ui/ScrollProgress'
import ScrollToTop from '@/components/ui/ScrollToTop'
import Chatbot from '@/components/ui/Chatbot'
import Hero from '@/components/sections/Hero'
import StatsBar from '@/components/sections/StatsBar'
import ScrollStory from '@/components/sections/ScrollStory'
import IntegrationsBar from '@/components/sections/IntegrationsBar'
import Features from '@/components/sections/Features'
import ExpandingShowcase from '@/components/sections/ExpandingShowcase'
import ThreatIntelSection from '@/components/sections/ThreatIntelSection'
import LogAnalysisSection from '@/components/sections/LogAnalysisSection'
import OpenCTISection from '@/components/sections/OpenCTISection'
import GlobalThreatMap from '@/components/sections/GlobalThreatMap'
import IOCNetworkSection from '@/components/sections/IOCNetworkSection'
import DashboardPreview from '@/components/sections/DashboardPreview'
import HowItWorks from '@/components/sections/HowItWorks'
import Pricing from '@/components/sections/Pricing'
import About from '@/components/sections/About'
import Contact from '@/components/sections/Contact'
import CTA from '@/components/sections/CTA'

export default function Home() {
  // Native scrolling on purpose: the Lenis smooth-scroll wrapper animated every
  // wheel tick over ~1.2s, which read as input lag and kept the "scrolling"
  // signal high so the WebGL scenes froze for the whole glide. Framer's
  // scroll-linked sections read native scroll just as well.
  return (
    <>
      <Preloader />
      <ScrollProgress />
      <CursorGlow />
      <CursorParticles />
      <LandingSidebar />
      <Navbar />
      <main id="main-content">
        <Hero />
        <StatsBar />
        <IntegrationsBar />
        <ScrollStory />
        <Features />
        <ExpandingShowcase />
        <ThreatIntelSection />
        <LogAnalysisSection />
        <OpenCTISection />
        <GlobalThreatMap />
        <IOCNetworkSection />
        <DashboardPreview />
        <HowItWorks />
        <Pricing />
        <About />
        <Contact />
        <CTA />
      </main>
      <Footer />
      <ScrollToTop />
      <Chatbot />
    </>
  )
}
