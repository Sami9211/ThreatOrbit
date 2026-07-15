import coreWebVitals from 'eslint-config-next/core-web-vitals'
import nextTs from 'eslint-config-next/typescript'

const config = [
  { ignores: ['node_modules/**', 'out/**', '.next/**', 'test-results/**', 'playwright-report/**'] },
  ...coreWebVitals,
  ...nextTs,
  {
    rules: {
      // React-Compiler-era rules (react-hooks v7). The patterns they flag
      // here are deliberate: mount-time environment detection (usePerf),
      // per-mount randomised WebGL scenes (ssr:false, so no hydration risk),
      // Date.now() cutoffs over live data, and motion-value ref plumbing.
      // Keep them visible as warnings; the error gate is reserved for rules
      // whose findings are always bugs.
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/immutability': 'warn',
      // Aspirational: typed incrementally, not a merge blocker.
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
  {
    // Playwright fixtures destructure a `use` callback that the React-hooks
    // heuristic mistakes for React's `use` hook.
    files: ['e2e/**'],
    rules: { 'react-hooks/rules-of-hooks': 'off' },
  },
]

export default config
