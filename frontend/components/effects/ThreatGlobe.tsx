'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

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
  mid.normalize().multiplyScalar(R + dist * 0.45)
  return new THREE.QuadraticBezierCurve3(start, mid, end)
}

function Arc({ delay, color }: { delay: number; color: string }) {
  const lineRef  = useRef<THREE.Line>(null)
  const headRef  = useRef<THREE.Mesh>(null)
  const state    = useRef({ curve: makeArc(), t: -delay })
  const geom     = useMemo(() => new THREE.BufferGeometry(), [])

  const setLine = (curve: THREE.QuadraticBezierCurve3) => {
    geom.setFromPoints(curve.getPoints(48))
  }
  useMemo(() => setLine(state.current.curve), []) // eslint-disable-line

  useFrame((_, dt) => {
    const s = state.current
    s.t += dt * 0.5
    if (s.t > 1.4) { s.curve = makeArc(); setLine(s.curve); s.t = 0 }
    const tt = Math.max(0, Math.min(1, s.t))
    if (headRef.current) {
      headRef.current.position.copy(s.curve.getPoint(tt))
      ;(headRef.current.material as THREE.MeshBasicMaterial).opacity = Math.sin(tt * Math.PI)
    }
    if (lineRef.current) {
      // Envelope must reach 0 at both ends of the cycle: the arc teleports to
      // a new random curve on reset, and a nonzero floor (was 0.12) made that
      // swap a visible pop — a dim line snapping across the globe.
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
    t.current += dt * 1.5
    const s = 1 + 0.6 * Math.abs(Math.sin(t.current))
    ringRef.current.scale.setScalar(s)
    ;(ringRef.current.material as THREE.MeshBasicMaterial).opacity = 0.7 - 0.5 * Math.abs(Math.sin(t.current))
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
  const pts = useMemo(() => Array.from({ length: count }, () => randSpherePoint(R * 1.005)), [count])
  return (
    <group>
      {pts.map((p, i) => (
        <mesh key={i} position={p}>
          <sphereGeometry args={[0.018, 8, 8]} />
          <meshBasicMaterial color={ARC_COLORS[i % ARC_COLORS.length]} toneMapped={false} />
        </mesh>
      ))}
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
    if (groupRef.current && animate) groupRef.current.rotation.y += dt * 0.08
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
  // `mounted` latch — same fix as the other scenes): a scroll-away must never
  // tear down the context, or scrolling back shows a blank while it rebuilds.
  // The render loop pauses off-screen instead (frameloop demand).
  const { ref, visible } = useInViewport<HTMLDivElement>('800px')
  const [mounted, setMounted] = useState(false)
  useEffect(() => { if (visible) setMounted(true) }, [visible])
  const [degraded, setDegraded] = useState(false)

  const animate   = !prefersReducedMotion
  const arcCount  = isLowPower ? 8 : 20
  const nodeCount = isLowPower ? 25 : 55
  const bloomOn   = !isLowPower && !degraded

  return (
    <div ref={ref} className="w-full h-full">
      {mounted ? (
        <Canvas
          frameloop={animate && visible ? 'always' : 'demand'}
          camera={{ position: [0, 0, 6.2], fov: 42 }}
          gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
          // Phone sharpness: cap dpr at 1.75–2 (was 1.25–1.5, visibly pixelated
          // on dpr≈3 phones); AdaptiveDpr still lowers it under real load.
          dpr={degraded ? 1 : isLowPower ? [1, 1.75] : [1, 2]}
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
