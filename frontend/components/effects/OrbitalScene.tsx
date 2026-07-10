'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { AdaptiveDpr, PerformanceMonitor, PointMaterial } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

/* ── Orbit definitions: a planet circled by rings of dots ── */
type OrbitDef = {
  radius: number
  count:  number
  tilt:   [number, number, number]
  color:  string
  speed:  number
  dot:    number
  moon?:  boolean
}

const ORBITS: OrbitDef[] = [
  { radius: 1.15, count: 40, tilt: [Math.PI * 0.5,  0,            0],            color: '#FF2E97', speed:  0.42, dot: 0.028, moon: true },
  { radius: 1.55, count: 56, tilt: [Math.PI * 0.42, Math.PI * 0.18, 0],         color: '#7A3CFF', speed: -0.30, dot: 0.024, moon: true },
  { radius: 1.95, count: 72, tilt: [Math.PI * 0.58, -Math.PI * 0.22, 0],        color: '#FFB23E', speed:  0.24, dot: 0.020 },
  { radius: 2.35, count: 88, tilt: [Math.PI * 0.46, Math.PI * 0.35,  Math.PI * 0.1], color: '#2DD4BF', speed: -0.18, dot: 0.018, moon: true },
]

/* ── A ring of dots orbiting in its own tilted plane ── */
function DotOrbit({ radius, count, tilt, color, speed, dot, moon, animate }: OrbitDef & { animate: boolean }) {
  const spinRef = useRef<THREE.Group>(null)

  // Dots laid out in the XZ plane; the group rotation around Y makes them orbit.
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      const a = (i / count) * Math.PI * 2
      arr[i * 3]     = Math.cos(a) * radius
      arr[i * 3 + 1] = 0
      arr[i * 3 + 2] = Math.sin(a) * radius
    }
    return arr
  }, [count, radius])

  useFrame((_, dt) => {
    if (spinRef.current && animate) spinRef.current.rotation.y += dt * speed
  })

  return (
    <group rotation={tilt}>
      {/* faint orbit path */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius, 0.0035, 8, 160]} />
        <meshBasicMaterial color={color} transparent opacity={0.22} toneMapped={false} />
      </mesh>

      {/* the orbiting dots — PointMaterial masks each point to a circle;
         raw pointsMaterial renders gl.POINTS as squares, which read as
         little boxes riding the orbit ring */}
      <group ref={spinRef}>
        <points>
          <bufferGeometry>
            <bufferAttribute attach="attributes-position" args={[positions, 3]} />
          </bufferGeometry>
          <PointMaterial transparent size={dot} color={color} sizeAttenuation depthWrite={false} toneMapped={false} />
        </points>

        {/* a brighter "moon" riding the orbit */}
        {moon && (
          <mesh position={[radius, 0, 0]}>
            <sphereGeometry args={[0.06, 16, 16]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={5} toneMapped={false} />
          </mesh>
        )}
      </group>
    </group>
  )
}

/* ── The central planet ── */
function Planet({ animate, bright }: { animate: boolean; bright: boolean }) {
  const shellRef = useRef<THREE.Mesh>(null)
  const coreRef  = useRef<THREE.Mesh>(null)
  const t = useRef(0)

  useFrame((_, dt) => {
    if (!animate) return
    t.current += dt
    if (shellRef.current) shellRef.current.rotation.y += dt * 0.08
    if (coreRef.current) {
      const s = 0.97 + 0.03 * Math.sin(t.current * 1.6)
      coreRef.current.scale.setScalar(s)
    }
  })

  return (
    <group>
      {/* glowing core — without bloom, a hot emissive saturates every pixel
         and the sphere flattens into a featureless disc; keep the emissive
         moderate and let the directional light (added when bloom is off)
         shade the limb so it still reads as a sphere */}
      <mesh ref={coreRef}>
        <sphereGeometry args={[0.62, 48, 48]} />
        <meshStandardMaterial
          color="#2A1244"
          emissive="#FF2E97"
          emissiveIntensity={bright ? 0.55 : 0.6}
          metalness={0.7}
          roughness={0.25}
          toneMapped={false}
        />
      </mesh>

      {/* wireframe latitude shell */}
      <mesh ref={shellRef}>
        <icosahedronGeometry args={[0.67, 2]} />
        <meshBasicMaterial color="#FF6FC0" wireframe transparent opacity={0.3} toneMapped={false} />
      </mesh>

      {/* inner atmosphere */}
      <mesh>
        <sphereGeometry args={[0.75, 32, 32]} />
        <meshBasicMaterial color="#7A3CFF" transparent opacity={0.07} side={THREE.BackSide} />
      </mesh>

      {/* outer halo */}
      <mesh>
        <sphereGeometry args={[0.92, 32, 32]} />
        <meshBasicMaterial color="#FF2E97" transparent opacity={0.03} side={THREE.BackSide} />
      </mesh>
    </group>
  )
}

function PlanetSystem({ scrollY, mouseX, mouseY, animate, orbits, bright }: {
  scrollY: MotionValue<number>
  mouseX:  MotionValue<number>
  mouseY:  MotionValue<number>
  animate: boolean
  orbits:  OrbitDef[]
  bright:  boolean
}) {
  const groupRef = useRef<THREE.Group>(null)

  useFrame(() => {
    if (!groupRef.current) return
    groupRef.current.rotation.y = (scrollY.get() * Math.PI) / 180
    groupRef.current.rotation.x += (mouseY.get() * 0.5 - groupRef.current.rotation.x) * 0.06
    groupRef.current.rotation.z += (mouseX.get() * -0.28 - groupRef.current.rotation.z) * 0.06
  })

  return (
    <group ref={groupRef}>
      <Planet animate={animate} bright={bright} />
      {orbits.map((o, i) => <DotOrbit key={i} {...o} animate={animate} />)}
    </group>
  )
}

export default function OrbitalScene({ scrollY, mouseX, mouseY }: {
  scrollY: MotionValue<number>
  mouseX:  MotionValue<number>
  mouseY:  MotionValue<number>
}) {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  // Mount the GL context near the viewport, then KEEP it mounted (latch) so a
  // sudden scroll never tears down and rebuilds the context - which showed as
  // the orbit briefly vanishing. Render loop pauses (frameloop demand) while
  // off-screen, so the last frame stays put at zero GPU cost.
  const { ref, visible } = useInViewport<HTMLDivElement>('800px')
  const [mounted, setMounted] = useState(false)
  useEffect(() => { if (visible) setMounted(true) }, [visible])
  const [degraded, setDegraded] = useState(false)

  const animate   = !prefersReducedMotion
  const bloomOn   = !isLowPower && !degraded
  // brighten materials whenever bloom is off, so the scene stays visible
  const bright    = !bloomOn
  const orbits    = isLowPower ? ORBITS.slice(0, 3).map(o => ({ ...o, count: Math.round(o.count * 0.6) })) : ORBITS
  // Pull the camera back far enough that the outermost orbit clears the canvas
  // edge with margin (otherwise the orbit ring is hard-clipped into a visible
  // box). Low-power shows only 3 orbits, so it can sit closer / look larger.
  const camZ = isLowPower ? 6.0 : 7.4

  return (
    <div ref={ref} className="w-full h-full">
      {mounted ? (
        <Canvas
          frameloop={animate && visible ? 'always' : 'demand'}
          camera={{ position: [0, 0.8, camZ], fov: 46 }}
          gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
          // Phone sharpness: cap dpr at 1.75–2 (was 1.25–1.5, visibly pixelated
          // on dpr≈3 phones); AdaptiveDpr still lowers it under real load.
          dpr={degraded ? 1 : isLowPower ? [1, 1.75] : [1, 2]}
          style={{ background: 'transparent', width: '100%', height: '100%' }}
        >
          <ambientLight intensity={0.12} />
          <pointLight position={[4,  4, 4]}  intensity={2.2} color="#FF2E97" />
          <pointLight position={[-4, -2, 2]} intensity={1.5} color="#7A3CFF" />
          <pointLight position={[0, 0, -4]}  intensity={0.9} color="#FFB23E" />
          {/* bloom-off fallback: point lights decay to almost nothing at this
             distance, so add a directional key light to shade the planet */}
          {bright && <directionalLight position={[3, 4, 5]} intensity={2.2} color="#FF9ACF" />}
          <PlanetSystem
            scrollY={scrollY} mouseX={mouseX} mouseY={mouseY}
            animate={animate} orbits={orbits} bright={bright}
          />
          {bloomOn && (
            <EffectComposer>
              <Bloom intensity={1.9} luminanceThreshold={0.15} luminanceSmoothing={0.9} mipmapBlur />
            </EffectComposer>
          )}
          <PerformanceMonitor onDecline={() => setDegraded(true)} />
          <AdaptiveDpr />
        </Canvas>
      ) : (
        <ScenePlaceholder />
      )}
    </div>
  )
}
