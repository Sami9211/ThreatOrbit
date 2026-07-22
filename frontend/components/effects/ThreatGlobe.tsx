'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { usePerfProfile, useInViewport, clampDelta } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'
import RoundPoints from '@/components/effects/RoundPoints'

const R = 2
const ARC_COLORS = ['#FF2E97', '#7A3CFF', '#FFB23E', '#2DD4BF']

/* Convert lat/lon degrees to a 3-vector on the sphere */
function latLonToVec(lat: number, lon: number, radius = R): THREE.Vector3 {
  const phi   = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
     radius * Math.cos(phi),
     radius * Math.sin(phi) * Math.sin(theta),
  )
}

/* Known city hotspots (attack origins / targets) */
const HOTSPOTS = [
  { lat:  40.7, lon: -74.0, color: '#FF2E97' }, // New York
  { lat:  51.5, lon:  -0.1, color: '#7A3CFF' }, // London
  { lat:  35.7, lon: 139.7, color: '#FFB23E' }, // Tokyo
  { lat:  52.5, lon:  13.4, color: '#2DD4BF' }, // Berlin
  { lat:  55.8, lon:  37.6, color: '#FF4D6D' }, // Moscow
  { lat:  31.2, lon: 121.5, color: '#FF2E97' }, // Shanghai
  { lat:  1.35, lon: 103.8, color: '#7A3CFF' }, // Singapore
  { lat: -33.9, lon:  18.4, color: '#FFB23E' }, // Cape Town
  { lat:  19.4, lon: -99.1, color: '#2DD4BF' }, // Mexico City
  { lat: -23.5, lon: -46.6, color: '#FF2E97' }, // São Paulo
  { lat:  28.6, lon:  77.2, color: '#7A3CFF' }, // New Delhi
  { lat:  37.6, lon: 126.9, color: '#FFB23E' }, // Seoul
]

function randSpherePoint(radius = R): THREE.Vector3 {
  const u = Math.random()
  const v = Math.random()
  const theta = 2 * Math.PI * u
  const phi   = Math.acos(2 * v - 1)
  return new THREE.Vector3(
    radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.sin(phi) * Math.sin(theta),
    radius * Math.cos(phi),
  )
}

function makeArc(): THREE.QuadraticBezierCurve3 {
  const start = randSpherePoint()
  const end   = randSpherePoint()
  const mid   = start.clone().add(end).multiplyScalar(0.5)
  const dist  = start.distanceTo(end)
  // Cap the apex: uncapped (R + dist*0.45 reached 3.8 world units) the tall
  // arcs overflowed the camera frustum and were hard-cut at the canvas edge -
  // one of the "box around the globe" contributors.
  mid.normalize().multiplyScalar(Math.min(R + dist * 0.3, R * 1.16))
  return new THREE.QuadraticBezierCurve3(start, mid, end)
}

const rand = (a: number, b: number) => a + Math.random() * (b - a)

function Arc({ delay, color }: { delay: number; color: string }) {
  const lineRef  = useRef<THREE.Line>(null)
  const headRef  = useRef<THREE.Mesh>(null)
  // Per-arc random speed + rest, re-rolled every cycle: with one shared period
  // (it was exactly 2.8s for every arc) the whole ensemble phase-locked into a
  // visibly repeating ~2s loop with a synchronized dead gap. Incommensurate
  // periods never realign, so the traffic reads as continuous.
  const state    = useRef({ curve: makeArc(), t: -delay - rand(0, 2),
                            speed: rand(0.3, 0.55), rest: rand(0.1, 0.5) })
  const geom     = useMemo(() => new THREE.BufferGeometry(), [])

  const setLine = (curve: THREE.QuadraticBezierCurve3) => {
    geom.setFromPoints(curve.getPoints(48))
  }
  useMemo(() => setLine(state.current.curve), []) // eslint-disable-line

  useFrame((_, dt) => {
    const s = state.current
    s.t += clampDelta(dt) * s.speed
    if (s.t > 1 + s.rest) {
      s.curve = makeArc(); setLine(s.curve)
      s.t = -rand(0.05, 0.6)
      s.speed = rand(0.3, 0.55)
      s.rest = rand(0.1, 0.5)
    }
    const tt = Math.max(0, Math.min(1, s.t))
    if (headRef.current) {
      headRef.current.position.copy(s.curve.getPoint(tt))
      ;(headRef.current.material as THREE.MeshBasicMaterial).opacity = Math.sin(tt * Math.PI)
    }
    if (lineRef.current) {
      // Envelope must reach 0 at both ends of the cycle: the arc teleports to
      // a new random curve on reset, and a nonzero floor (was 0.12) made that
      // swap a visible pop - a dim line snapping across the globe.
      ;(lineRef.current.material as THREE.LineBasicMaterial).opacity =
        0.44 * Math.sin(tt * Math.PI)
    }
  })

  return (
    <group>
      {/* @ts-expect-error R3F line intrinsic */}
      <line ref={lineRef} geometry={geom}>
        <lineBasicMaterial color={color} transparent opacity={0} toneMapped={false} />
      </line>
      <mesh ref={headRef}>
        <sphereGeometry args={[0.04, 12, 12]} />
        <meshBasicMaterial color={color} transparent toneMapped={false} />
      </mesh>
    </group>
  )
}

/* Latitude / Longitude grid lines */
function GlobeGrid() {
  const geom = useMemo(() => {
    const pts: THREE.Vector3[] = []
    const SEGS = 64

    // Latitude lines every 30°
    for (let lat = -60; lat <= 60; lat += 30) {
      for (let i = 0; i <= SEGS; i++) {
        const lon = (i / SEGS) * 360 - 180
        pts.push(latLonToVec(lat, lon, R * 1.001))
        if (i > 0 && i < SEGS) pts.push(latLonToVec(lat, lon, R * 1.001)) // duplicate for line segments
      }
    }

    // Longitude lines every 60°
    for (let lon = -180; lon < 180; lon += 60) {
      for (let i = 0; i <= SEGS; i++) {
        const lat = (i / SEGS) * 180 - 90
        pts.push(latLonToVec(lat, lon, R * 1.001))
        if (i > 0 && i < SEGS) pts.push(latLonToVec(lat, lon, R * 1.001))
      }
    }

    const g = new THREE.BufferGeometry().setFromPoints(pts)
    return g
  }, [])

  return (
    <lineSegments geometry={geom}>
      <lineBasicMaterial color="#7A3CFF" transparent opacity={0.07} toneMapped={false} />
    </lineSegments>
  )
}

/* Pulsing city hotspot indicators */
function Hotspot({ lat, lon, color, animate }: { lat: number; lon: number; color: string; animate: boolean }) {
  const ringRef = useRef<THREE.Mesh>(null)
  const t = useRef(Math.random() * Math.PI * 2)

  useFrame((_, dt) => {
    if (!ringRef.current || !animate) return
    t.current += clampDelta(dt) * 1.5
    // sin², not |sin|: same 0→1→0 breathing range/period, but it touches both
    // extremes tangentially (zero derivative) - no sharp cusp at the bottom of
    // each pulse, which read as a repeating "snap". Smooth breathe.
    const sn = Math.sin(t.current)
    const pulse = sn * sn
    ringRef.current.scale.setScalar(1 + 0.6 * pulse)
    ;(ringRef.current.material as THREE.MeshBasicMaterial).opacity = 0.7 - 0.5 * pulse
  })

  const pos = latLonToVec(lat, lon, R * 1.01)
  const normal = pos.clone().normalize()

  return (
    <group position={pos} quaternion={new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal)}>
      {/* Core dot */}
      <mesh>
        <circleGeometry args={[0.028, 12]} />
        <meshBasicMaterial color={color} toneMapped={false} />
      </mesh>
      {/* Pulse ring */}
      <mesh ref={ringRef}>
        <ringGeometry args={[0.035, 0.058, 16]} />
        <meshBasicMaterial color={color} transparent opacity={0.7} side={THREE.DoubleSide} toneMapped={false} />
      </mesh>
    </group>
  )
}

function Nodes({ count }: { count: number }) {
  // Round point sprites, not tiny sphere meshes: at this size (was radius 0.018)
  // meshes aliased into visible squares through the bloom pass. See RoundPoints.
  const { positions, colors, sizes } = useMemo(() => {
    const positions = new Float32Array(count * 3)
    const colors = new Float32Array(count * 3)
    const sizes = new Float32Array(count)
    const col = new THREE.Color()
    for (let i = 0; i < count; i++) {
      const p = randSpherePoint(R * 1.005)
      positions[i * 3] = p.x; positions[i * 3 + 1] = p.y; positions[i * 3 + 2] = p.z
      col.set(ARC_COLORS[i % ARC_COLORS.length])
      colors[i * 3] = col.r; colors[i * 3 + 1] = col.g; colors[i * 3 + 2] = col.b
      sizes[i] = 0.09
    }
    return { positions, colors, sizes }
  }, [count])
  return (
    <group>
      <RoundPoints positions={positions} colors={colors} sizes={sizes} />
    </group>
  )
}

function GlobeGroup({ arcCount, nodeCount, animate }: {
  arcCount:  number
  nodeCount: number
  animate:   boolean
}) {
  const groupRef = useRef<THREE.Group>(null)
  useFrame((_, dt) => {
    if (groupRef.current && animate) groupRef.current.rotation.y += clampDelta(dt) * 0.08
  })
  return (
    <group ref={groupRef} rotation={[0.28, 0, 0.06]}>
      {/* Wireframe icosphere */}
      <mesh>
        <icosahedronGeometry args={[R, 6]} />
        <meshBasicMaterial color="#4A2CCC" wireframe transparent opacity={0.10} />
      </mesh>
      {/* Inner solid sphere */}
      <mesh>
        <sphereGeometry args={[R * 0.985, 48, 48]} />
        <meshBasicMaterial color="#0A0612" />
      </mesh>
      {/* Atmosphere glow */}
      <mesh>
        <sphereGeometry args={[R * 1.055, 48, 48]} />
        <meshBasicMaterial color="#7A3CFF" transparent opacity={0.03} side={THREE.BackSide} />
      </mesh>
      {/* Outer halo */}
      <mesh>
        <sphereGeometry args={[R * 1.12, 48, 48]} />
        <meshBasicMaterial color="#FF2E97" transparent opacity={0.012} side={THREE.BackSide} />
      </mesh>
      {/* Lat/lon grid */}
      <GlobeGrid />
      {/* City hotspots */}
      {HOTSPOTS.map((h, i) => (
        <Hotspot key={i} {...h} animate={animate} />
      ))}
      <Nodes count={nodeCount} />
      {animate && Array.from({ length: arcCount }).map((_, i) => (
        <Arc key={i} delay={i * 0.22} color={ARC_COLORS[i % ARC_COLORS.length]} />
      ))}
    </group>
  )
}

export default function ThreatGlobe() {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  // Mount the GL context well before the viewport, then KEEP it mounted (the
  // `mounted` latch - same fix as the other scenes): a scroll-away must never
  // tear down the context, or scrolling back shows a blank while it rebuilds.
  // The render loop pauses off-screen instead (frameloop demand).
  const { ref, visible } = useInViewport<HTMLDivElement>('800px')
  // NOTE: no pause-while-scrolling - frozen scenes mid-scroll read as broken.
  // Cost is managed by the dpr cap + AdaptiveDpr/PerformanceMonitor instead.
  const [mounted, setMounted] = useState(false)
  useEffect(() => { if (visible) setMounted(true) }, [visible])
  const [degraded, setDegraded] = useState(false)

  const animate   = !prefersReducedMotion
  const arcCount  = isLowPower ? 8 : 20
  const nodeCount = isLowPower ? 25 : 55
  const bloomOn   = !isLowPower && !degraded

  // Fade the canvas to transparent before its rectangle ends (same fix as
  // OrbitalScene): bloom glow + arc lines otherwise terminate in a hard
  // straight edge at the canvas boundary - the visible box around the globe.
  const edgeFade = {
    maskImage: 'radial-gradient(closest-side circle at 50% 50%, #000 80%, transparent 99%)',
    WebkitMaskImage: 'radial-gradient(closest-side circle at 50% 50%, #000 80%, transparent 99%)',
  } as const

  return (
    <div ref={ref} className="w-full h-full" style={edgeFade}>
      {mounted ? (
        <Canvas
          frameloop={animate && visible ? 'always' : 'demand'}
          camera={{ position: [0, 0, 6.2], fov: 42 }}
          gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
          // Phone sharpness: cap dpr at 1.75-2 (was 1.25-1.5, visibly pixelated
          // on dpr≈3 phones); AdaptiveDpr still lowers it under real load.
          dpr={degraded ? 1 : [1, 1.75]}
          style={{ background: 'transparent', width: '100%', height: '100%' }}
        >
          <ambientLight intensity={0.5} />
          <GlobeGroup arcCount={arcCount} nodeCount={nodeCount} animate={animate} />
          <OrbitControls enableZoom={false} enablePan={false} autoRotate={false} rotateSpeed={0.5} />
          {bloomOn && (
            <EffectComposer>
              <Bloom intensity={2.0} luminanceThreshold={0.08} luminanceSmoothing={0.9} mipmapBlur />
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
