'use client'

import { useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Float, AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import type { MotionValue } from 'framer-motion'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

/* ── Floating solid objects ── */
const OBJECTS = [
  { p: [ 2.7,  0.5,  0.0], s: 0.62, g: 'hex',  c: '#FF2E97', fs: 1.4, wire: false },
  { p: [-2.7,  1.2, -1.0], s: 0.34, g: 'hex',  c: '#7A3CFF', fs: 1.0, wire: true  },
  { p: [ 2.1, -1.9, -0.4], s: 0.26, g: 'oct',  c: '#FFB23E', fs: 1.6, wire: false },
  { p: [-1.7, -1.1,  0.3], s: 0.20, g: 'ico',  c: '#2DD4BF', fs: 1.2, wire: false },
  { p: [ 3.4, -0.5, -1.2], s: 0.15, g: 'oct',  c: '#FF2E97', fs: 1.8, wire: true  },
  { p: [-0.7,  2.3, -0.6], s: 0.14, g: 'ico',  c: '#7A3CFF', fs: 0.9, wire: false },
  { p: [ 0.9, -2.5, -0.8], s: 0.12, g: 'hex',  c: '#FFB23E', fs: 1.5, wire: false },
  { p: [-3.4, -0.8, -0.5], s: 0.17, g: 'oct',  c: '#FF2E97', fs: 1.1, wire: true  },
  { p: [ 1.4,  2.0, -1.4], s: 0.13, g: 'ico',  c: '#2DD4BF', fs: 1.3, wire: false },
  { p: [-2.0,  0.1, -1.6], s: 0.11, g: 'hex',  c: '#7A3CFF', fs: 1.7, wire: true  },
]

function SceneObject({ p, s, g, c, fs, wire, animate, bright }: typeof OBJECTS[0] & { animate: boolean; bright: boolean }) {
  // When bloom is off (phone / degraded), push emissive up so shapes stay visible.
  const emissive = wire ? (bright ? 1.6 : 0.9) : (bright ? 1.0 : 0.45)
  return (
    <Float speed={animate ? fs : 0} floatIntensity={animate ? 0.7 : 0} rotationIntensity={animate ? 0.6 : 0}>
      <mesh position={p as [number, number, number]} scale={s}>
        {g === 'hex' && <cylinderGeometry args={[1, 1, 0.5, 6, 1]} />}
        {g === 'oct' && <octahedronGeometry args={[1, 0]} />}
        {g === 'ico' && <icosahedronGeometry args={[1, 0]} />}
        <meshStandardMaterial
          color={c} metalness={0.78} roughness={0.14}
          emissive={c} emissiveIntensity={emissive}
          wireframe={wire} flatShading toneMapped={false}
        />
      </mesh>
    </Float>
  )
}

/* ── Large slow-drifting wireframe torus knot for depth ── */
function BackdropKnot({ animate }: { animate: boolean }) {
  const ref = useRef<THREE.Mesh>(null)
  useFrame((_, dt) => {
    if (ref.current && animate) {
      ref.current.rotation.x += dt * 0.04
      ref.current.rotation.y += dt * 0.06
    }
  })
  return (
    <mesh ref={ref} position={[0, 0, -3]} scale={2.4}>
      <torusKnotGeometry args={[1, 0.18, 64, 12]} />
      <meshStandardMaterial
        color="#7A3CFF" emissive="#7A3CFF" emissiveIntensity={0.4}
        wireframe transparent opacity={0.12} toneMapped={false}
      />
    </mesh>
  )
}

/* ── Distant starfield ── */
function Stars({ count }: { count: number }) {
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      arr[i * 3]     = (Math.random() - 0.5) * 16
      arr[i * 3 + 1] = (Math.random() - 0.5) * 12
      arr[i * 3 + 2] = -3 - Math.random() * 6
    }
    return arr
  }, [count])
  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.03} color="#B4A8C8" transparent opacity={0.5} sizeAttenuation />
    </points>
  )
}

function SceneMesh({ mouseX, mouseY, animate, objects, bright }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
  animate: boolean
  objects: typeof OBJECTS
  bright: boolean
}) {
  const groupRef = useRef<THREE.Group>(null)
  useFrame(() => {
    if (!groupRef.current || !animate) return
    groupRef.current.rotation.x += (mouseY.get() * 0.15 - groupRef.current.rotation.x) * 0.03
    groupRef.current.rotation.y += (mouseX.get() * 0.2 - groupRef.current.rotation.y) * 0.03
  })
  return (
    <group ref={groupRef}>
      {objects.map((o, i) => <SceneObject key={i} {...o} animate={animate} bright={bright} />)}
    </group>
  )
}

export default function HeroScene({ mouseX, mouseY }: {
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  // Generous margin so the canvas mounts just before it scrolls into view and
  // unmounts (freeing its WebGL context) once well off-screen — keeps the page
  // from holding several live GL contexts at once.
  const { ref, visible } = useInViewport<HTMLDivElement>('400px')
  const [degraded, setDegraded] = useState(false)

  const objects   = isLowPower ? OBJECTS.slice(0, 6) : OBJECTS
  const animate   = !prefersReducedMotion
  const bloomOn   = !isLowPower && !degraded
  const bright    = !bloomOn   // brighten emissive when bloom can't carry the glow
  const starCount = isLowPower ? 50 : 120
  // Full-screen canvas → keep pixel count modest; bloom cost scales with pixels².
  const dpr: [number, number] | number = degraded ? 1 : isLowPower ? [1, 1.25] : [1, 1.5]

  return (
    <div ref={ref} className="w-full h-full">
      {visible ? (
        <Canvas
          frameloop={animate ? 'always' : 'demand'}
          camera={{ position: [0, 0, 6.5], fov: 56 }}
          gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
          dpr={dpr}
          style={{ background: 'transparent', width: '100%', height: '100%' }}
        >
          <ambientLight intensity={0.06} />
          <pointLight position={[ 5,  5,  5]} intensity={2.6} color="#FF2E97" />
          <pointLight position={[-5, -3,  3]} intensity={2.0} color="#7A3CFF" />
          <pointLight position={[ 0,  0, -5]} intensity={1.0} color="#FFB23E" />
          <Stars count={starCount} />
          {!isLowPower && <BackdropKnot animate={animate} />}
          <SceneMesh mouseX={mouseX} mouseY={mouseY} animate={animate} objects={objects} bright={bright} />
          {bloomOn && (
            <EffectComposer>
              <Bloom intensity={1.5} luminanceThreshold={0.2} luminanceSmoothing={0.85} mipmapBlur />
            </EffectComposer>
          )}
          <PerformanceMonitor onDecline={() => setDegraded(true)} />
          <AdaptiveDpr pixelated />
        </Canvas>
      ) : (
        <ScenePlaceholder />
      )}
    </div>
  )
}
