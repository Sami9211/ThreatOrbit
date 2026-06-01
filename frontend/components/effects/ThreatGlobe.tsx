'use client'

import { useMemo, useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'

const R = 2 // globe radius
const ARC_COLORS = ['#FF2E97', '#7A3CFF', '#FFB23E', '#2DD4BF']

/* random point on the sphere surface */
function randSpherePoint(radius = R): THREE.Vector3 {
  const u = Math.random()
  const v = Math.random()
  const theta = 2 * Math.PI * u
  const phi = Math.acos(2 * v - 1)
  return new THREE.Vector3(
    radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.sin(phi) * Math.sin(theta),
    radius * Math.cos(phi),
  )
}

/* a great-arc curve bowing outward from the surface */
function makeArc(): THREE.QuadraticBezierCurve3 {
  const start = randSpherePoint()
  const end = randSpherePoint()
  const mid = start.clone().add(end).multiplyScalar(0.5)
  const dist = start.distanceTo(end)
  mid.normalize().multiplyScalar(R + dist * 0.45)
  return new THREE.QuadraticBezierCurve3(start, mid, end)
}

/* ── one animated attack arc with a traveling head ── */
function Arc({ delay, color }: { delay: number; color: string }) {
  const lineRef = useRef<THREE.Line>(null)
  const headRef = useRef<THREE.Mesh>(null)
  const state = useRef({ curve: makeArc(), t: -delay })

  // build the line geometry once, refresh its positions when the curve changes
  const geom = useMemo(() => new THREE.BufferGeometry(), [])
  const setLine = (curve: THREE.QuadraticBezierCurve3) => {
    const pts = curve.getPoints(48)
    geom.setFromPoints(pts)
  }
  useMemo(() => setLine(state.current.curve), []) // eslint-disable-line react-hooks/exhaustive-deps

  useFrame((_, dt) => {
    const s = state.current
    s.t += dt * 0.5
    if (s.t > 1.4) {
      s.curve = makeArc()
      setLine(s.curve)
      s.t = 0
    }
    const tt = Math.max(0, Math.min(1, s.t))
    if (headRef.current) {
      const p = s.curve.getPoint(tt)
      headRef.current.position.copy(p)
      const fade = Math.sin(tt * Math.PI) // bright in the middle
      ;(headRef.current.material as THREE.MeshBasicMaterial).opacity = fade
    }
    if (lineRef.current) {
      ;(lineRef.current.material as THREE.LineBasicMaterial).opacity =
        0.15 + 0.35 * Math.sin(Math.max(0, Math.min(1, s.t)) * Math.PI)
    }
  })

  return (
    <group>
      {/* @ts-expect-error R3F line intrinsic */}
      <line ref={lineRef} geometry={geom}>
        <lineBasicMaterial color={color} transparent opacity={0.3} toneMapped={false} />
      </line>
      <mesh ref={headRef}>
        <sphereGeometry args={[0.035, 12, 12]} />
        <meshBasicMaterial color={color} transparent toneMapped={false} />
      </mesh>
    </group>
  )
}

/* ── glowing static nodes scattered on the surface ── */
function Nodes({ count }: { count: number }) {
  const pts = useMemo(
    () => Array.from({ length: count }, () => randSpherePoint(R * 1.005)),
    [count],
  )
  return (
    <group>
      {pts.map((p, i) => (
        <mesh key={i} position={p}>
          <sphereGeometry args={[0.02, 8, 8]} />
          <meshBasicMaterial
            color={ARC_COLORS[i % ARC_COLORS.length]}
            toneMapped={false}
          />
        </mesh>
      ))}
    </group>
  )
}

function GlobeGroup({ arcCount, nodeCount, animate }: {
  arcCount: number
  nodeCount: number
  animate: boolean
}) {
  const groupRef = useRef<THREE.Group>(null)
  useFrame((_, dt) => {
    if (groupRef.current && animate) groupRef.current.rotation.y += dt * 0.08
  })
  return (
    <group ref={groupRef} rotation={[0.35, 0, 0.1]}>
      {/* wireframe globe */}
      <mesh>
        <icosahedronGeometry args={[R, 6]} />
        <meshBasicMaterial color="#7A3CFF" wireframe transparent opacity={0.12} />
      </mesh>
      {/* inner solid sphere to occlude back-side arcs */}
      <mesh>
        <sphereGeometry args={[R * 0.985, 48, 48]} />
        <meshBasicMaterial color="#0A0612" />
      </mesh>
      {/* faint atmosphere */}
      <mesh>
        <sphereGeometry args={[R * 1.04, 48, 48]} />
        <meshBasicMaterial color="#FF2E97" transparent opacity={0.04} side={THREE.BackSide} />
      </mesh>
      <Nodes count={nodeCount} />
      {animate &&
        Array.from({ length: arcCount }).map((_, i) => (
          <Arc key={i} delay={i * 0.22} color={ARC_COLORS[i % ARC_COLORS.length]} />
        ))}
    </group>
  )
}

export default function ThreatGlobe() {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  const { ref, visible } = useInViewport<HTMLDivElement>('200px')

  const animate = !prefersReducedMotion
  const arcCount = isLowPower ? 8 : 18
  const nodeCount = isLowPower ? 30 : 70
  const enableBloom = !isLowPower

  return (
    <div ref={ref} className="w-full h-full">
      <Canvas
        frameloop={visible && animate ? 'always' : 'demand'}
        camera={{ position: [0, 0, 6], fov: 42 }}
        gl={{ alpha: true, antialias: !isLowPower, powerPreference: 'high-performance' }}
        dpr={isLowPower ? [1, 1.5] : [1, 2]}
        style={{ background: 'transparent', width: '100%', height: '100%' }}
      >
        <ambientLight intensity={0.5} />
        <GlobeGroup arcCount={arcCount} nodeCount={nodeCount} animate={animate} />
        <OrbitControls
          enableZoom={false}
          enablePan={false}
          autoRotate={false}
          rotateSpeed={0.5}
        />
        {enableBloom && (
          <EffectComposer>
            <Bloom intensity={1.6} luminanceThreshold={0.1} luminanceSmoothing={0.9} mipmapBlur />
          </EffectComposer>
        )}
        <PerformanceMonitor />
        <AdaptiveDpr pixelated />
      </Canvas>
    </div>
  )
}
