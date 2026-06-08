/**
 * Shared subscription plan definitions used by the pricing page, the sign-up
 * flow, and the landing pricing section so they never tell contradictory
 * stories. Prices are monthly GBP.
 */
export type PlanId = 'free' | 'starter' | 'professional' | 'enterprise'

export type Plan = {
  id: PlanId
  name: string
  price: number | null // null = custom / contact sales
  priceLabel: string
  cadence: string
  tagline: string
  users: string
  highlight?: boolean
  badge?: string
  color: string
  features: string[]
}

export const PLANS: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    price: 0,
    priceLabel: '£0',
    cadence: 'forever',
    tagline: 'Start exploring threat intelligence with zero cost.',
    users: '1 user',
    color: '#34F5C5',
    features: [
      'IntelScope threat scanner',
      'IOC reputation lookups',
      'Community threat feeds',
      'Single user seat',
    ],
  },
  {
    id: 'starter',
    name: 'Starter',
    price: 149,
    priceLabel: '£149',
    cadence: '/mo starting',
    tagline: 'CTI, Feeds & Asset Surface for growing security teams.',
    users: 'Up to 3 users',
    color: '#FFB23E',
    features: [
      'Everything in Free',
      'CTI Intelligence module',
      'Real-time threat feeds',
      'Asset surface monitoring',
      'Asset vulnerability alerts',
    ],
  },
  {
    id: 'professional',
    name: 'Professional',
    price: 499,
    priceLabel: '£499',
    cadence: '/mo starting',
    tagline: 'Full-stack security ops. Everything but multi-tenant.',
    users: 'Up to 10 users',
    highlight: true,
    badge: 'Most Popular',
    color: '#FF2E97',
    features: [
      'Everything in Starter',
      'SIEM detection & alert queue',
      'SOAR playbooks & automation',
      'OpenCTI integration',
      'Dark web monitoring',
      'Full REST API access',
      '48h support SLA',
    ],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: null,
    priceLabel: 'Custom',
    cadence: 'contact us',
    tagline: 'White-glove onboarding, SLA, multi-tenant & dedicated support.',
    users: 'Unlimited users',
    color: '#7A3CFF',
    features: [
      'Everything in Professional',
      'Multi-tenant & white-label',
      'Role-based access control',
      'Dedicated success manager',
      '4h support SLA',
      'Custom integrations',
    ],
  },
]

export const planById = Object.fromEntries(PLANS.map((p) => [p.id, p])) as Record<PlanId, Plan>
